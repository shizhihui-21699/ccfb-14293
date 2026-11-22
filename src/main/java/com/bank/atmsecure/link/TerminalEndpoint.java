package com.bank.atmsecure.link;

import com.bank.atmsecure.auth.DispenseReceipt;
import com.bank.atmsecure.auth.HostAuthorization;
import com.bank.atmsecure.auth.ModuleCertificate;
import com.bank.atmsecure.auth.OfflineEnvelope;
import com.bank.atmsecure.dispenser.DispenseRequest;
import com.bank.atmsecure.dispenser.DispenseResult;
import com.bank.atmsecure.host.Host;
import com.bank.atmsecure.model.CashPlan;
import com.bank.atmsecure.model.Money;
import com.bank.atmsecure.model.Protocol;
import com.bank.atmsecure.model.TerminalId;
import com.bank.atmsecure.model.TxId;
import com.bank.atmsecure.wire.Handshake;
import com.bank.atmsecure.wire.Hello;
import com.bank.atmsecure.wire.HelloAck;
import com.bank.atmsecure.wire.LinkSession;
import com.bank.atmsecure.wire.MessageType;
import com.bank.atmsecure.wire.ProtoException;
import com.bank.atmsecure.wire.WireFrame;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.function.Consumer;

/**
 * Terminal (business-software) endpoint. <b>Explicitly untrusted by the dispenser.</b>
 *
 * <p>Stands in for code on the PC an attacker is assumed able to replace. It holds no long-term
 * signing secret — only the public manufacturing key used to authenticate the dispenser's
 * certificate. Everything it tells the host is a claim the host re-checks; everything it tells the
 * dispenser is checked against the host signature. A fully compromised instance of this class can
 * therefore make the ATM fail, but cannot make it dispense unauthorised cash.
 */
public final class TerminalEndpoint {
    private final TerminalId terminalId;
    private final SimLink link;
    private final PublicKey manufacturingKey;
    private final String softwareVersion;
    private final Consumer<String> trace;

    private KeyPair ephemeral;
    private byte[] random;
    private LinkSession session;
    private HelloAck moduleInfo;
    private ModuleCertificate dispenserCert;

    public TerminalEndpoint(TerminalId terminalId, SimLink link, PublicKey manufacturingKey) {
        this(terminalId, link, manufacturingKey, "atm-business/1.0", null);
    }

    public TerminalEndpoint(TerminalId terminalId, SimLink link, PublicKey manufacturingKey,
            String softwareVersion, Consumer<String> trace) {
        this.terminalId = terminalId;
        this.link = link;
        this.manufacturingKey = manufacturingKey;
        this.softwareVersion = softwareVersion;
        this.trace = trace;
    }

    public record Outcome(boolean dispensed, DispenseReceipt receipt, String detail,
            HelloAck moduleInfo) {
    }

    // ---------------------------------------------------------------------------------------------
    // Handshake
    // ---------------------------------------------------------------------------------------------

    /** Builds and transmits HELLO. */
    public byte[] hello() {
        ephemeral = com.bank.atmsecure.crypto.X25519.generate();
        random = new byte[32];
        new java.security.SecureRandom().nextBytes(random);
        byte[] ephRaw = com.bank.atmsecure.crypto.X25519.rawPublic(ephemeral.getPublic());
        Hello hello = new Hello(ephRaw, random, softwareVersion, Protocol.VERSION);
        byte[] bytes = hello.encode();
        link.transmit(bytes);
        return bytes;
    }

    /**
     * Authenticates the dispenser's HELLO_ACK, using the certificate pinned for this ATM, then
     * derives the link session.
     */
    public HelloAck acceptHelloAck(byte[] ackBytes, ModuleCertificate cert) {
        HelloAck ack = HelloAck.decode(ackBytes);
        if (!cert.verify(manufacturingKey)) {
            throw new ProtoException("dispenser certificate does not chain to pinned key");
        }
        if (!cert.moduleId().equals(ack.moduleId())) {
            throw new ProtoException("dispenser identity does not match its certificate");
        }
        byte[] ephRaw = com.bank.atmsecure.crypto.X25519.rawPublic(ephemeral.getPublic());
        if (!ack.verifyModuleSignature(cert.modulePublicKeyObject(), ephRaw, random)) {
            throw new ProtoException("dispenser handshake signature invalid");
        }
        byte[] transcript = ack.signedTranscript(ephRaw, random);
        PublicKey dispenserEph =
                com.bank.atmsecure.crypto.X25519.fromRawPublic(ack.moduleEphemeralPublic());
        session = LinkSession.establish(LinkSession.Role.TERMINAL, ephemeral, dispenserEph,
                transcript);
        moduleInfo = ack;
        dispenserCert = cert;
        if (trace != null) {
            trace.accept("TERMINAL: handshake ok session=" + Long.toUnsignedString(session.sessionId())
                    + " module=" + ack.moduleId() + " epoch=" + ack.keyEpoch()
                    + " status=" + ack.statusCode());
        }
        return ack;
    }

    // ---------------------------------------------------------------------------------------------
    // Dispense
    // ---------------------------------------------------------------------------------------------

    public byte[] transmit(DispenseRequest request) {
        requireSession();
        WireFrame f = session.seal(MessageType.DISPENSE, request.encode());
        byte[] bytes = f.encode();
        link.transmit(bytes);
        return bytes;
    }

    public DispenseResult receive(byte[] resultFrameBytes) {
        requireSession();
        WireFrame frame = WireFrame.decodeHeader(resultFrameBytes);
        return DispenseResult.decode(session.open(frame));
    }

    /** Online flow driven by the simulator. */
    public Outcome dispenseOnline(Simulator.DispenserSide side, Host host, String customerId,
            TxId txId, CashPlan plan) {
        if (!side.connect(this)) {
            return new Outcome(false, null, "handshake failed", moduleInfo);
        }
        if (moduleInfo.statusCode() != HelloAck.STATUS_OK) {
            return new Outcome(false, null, "module not ready (status " + moduleInfo.statusCode()
                    + ")", moduleInfo);
        }
        byte[] nonce = side.challenge();
        Host.OnlineRequest req = new Host.OnlineRequest(terminalId, moduleInfo.moduleId(),
                moduleInfo.keyEpoch(), txId, customerId, Money.ofCents(plan.totalCents()), plan,
                nonce, session.channelBinding());
        Host.Decision decision = host.authorize(req);
        if (!decision.approved()) {
            return new Outcome(false, null, "host refused: " + decision.reason(), moduleInfo);
        }
        return run(side, new DispenseRequest.Online(decision.authorization()));
    }

    public Outcome dispenseOffline(Simulator.DispenserSide side, OfflineEnvelope envelope,
            CashPlan plan) {
        if (!side.connect(this)) {
            return new Outcome(false, null, "handshake failed", moduleInfo);
        }
        if (moduleInfo.statusCode() != HelloAck.STATUS_OK) {
            return new Outcome(false, null, "module not ready (status " + moduleInfo.statusCode()
                    + ")", moduleInfo);
        }
        return run(side, new DispenseRequest.Offline(envelope, plan));
    }

    /** Sends an arbitrary request and returns the outcome (used for attack injections too). */
    public Outcome submit(Simulator.DispenserSide side, DispenseRequest request) {
        if (session == null && !side.connect(this)) {
            return new Outcome(false, null, "handshake failed", moduleInfo);
        }
        return run(side, request);
    }

    private Outcome run(Simulator.DispenserSide side, DispenseRequest request) {
        byte[] requestFrame = transmit(request);
        byte[] resultFrame = side.process(requestFrame);
        DispenseResult result = receive(resultFrame);
        if (result.ok() && result.receipt() != null) {
            return new Outcome(true, result.receipt(), "", moduleInfo);
        }
        return new Outcome(false, null, result.status() + " " + result.detail(), moduleInfo);
    }

    // ---------------------------------------------------------------------------------------------
    // Accessors
    // ---------------------------------------------------------------------------------------------

    public LinkSession session() {
        return session;
    }

    public HelloAck moduleInfo() {
        return moduleInfo;
    }

    public ModuleCertificate dispenserCert() {
        return dispenserCert;
    }

    public TerminalId terminalId() {
        return terminalId;
    }

    public KeyPair ephemeral() {
        return ephemeral;
    }

    public byte[] helloRandom() {
        return random == null ? null : random.clone();
    }

    public SimLink link() {
        return link;
    }

    public void resetSession() {
        this.session = null;
        this.moduleInfo = null;
    }

    private void requireSession() {
        if (session == null) {
            throw new IllegalStateException("handshake not completed");
        }
    }
}
