package com.bank.atmsecure.link;

import com.bank.atmsecure.dispenser.CashDispenserModule;
import com.bank.atmsecure.dispenser.DispenseRequest;
import com.bank.atmsecure.dispenser.DispenseResult;
import com.bank.atmsecure.model.Protocol;
import com.bank.atmsecure.wire.Handshake;
import com.bank.atmsecure.wire.Hello;
import com.bank.atmsecure.wire.HelloAck;
import com.bank.atmsecure.wire.LinkSession;
import com.bank.atmsecure.wire.MessageType;
import com.bank.atmsecure.wire.ProtoException;
import com.bank.atmsecure.wire.WireFrame;
import java.security.KeyPair;
import java.util.function.Consumer;

/**
 * Dispenser endpoint: runs the module's side of the handshake and de-frames inbound requests.
 *
 * <p>It contains no authorisation logic. Decrypt → hand to {@link CashDispenserModule} → seal the
 * result. The module is the trust boundary; this layer only protects confidentiality and session
 * integrity.
 */
public final class DispenserEndpoint {
    private final CashDispenserModule module;
    private final SimLink link;
    private final Consumer<String> trace;

    private KeyPair ephemeral;
    private LinkSession session;
    private HelloAck lastAck;

    public DispenserEndpoint(CashDispenserModule module, SimLink link) {
        this(module, link, null);
    }

    public DispenserEndpoint(CashDispenserModule module, SimLink link, Consumer<String> trace) {
        this.module = module;
        this.link = link;
        this.trace = trace;
    }

    /** Handles HELLO, emits HELLO_ACK, and opens the module's per-session challenge. */
    public byte[] onHello(byte[] helloBytes) {
        if (!module.admitHello()) {
            throw new ProtoException("HELLO refused (rate limited or module locked)");
        }
        Hello hello = Hello.decode(helloBytes);
        if (hello.protocolVersion() != Protocol.VERSION) {
            throw new ProtoException("terminal protocol version mismatch");
        }
        ephemeral = com.bank.atmsecure.crypto.X25519.generate();
        byte[] moduleEphRaw = com.bank.atmsecure.crypto.X25519.rawPublic(ephemeral.getPublic());
        byte[] moduleRandom = new byte[32];
        new java.security.SecureRandom().nextBytes(moduleRandom);

        byte[] transcript = Handshake.transcript(hello.terminalEphemeralPublic(), moduleEphRaw,
                hello.terminalRandom(), moduleRandom,
                module.moduleId().value().getBytes(java.nio.charset.StandardCharsets.UTF_8),
                module.keyEpoch());
        byte[] sig = module.signHandshakeTranscript(transcript);

        int status = module.isLocked() ? HelloAck.STATUS_TAMPERED
                : module.isPaired() ? HelloAck.STATUS_OK : HelloAck.STATUS_NOT_PAIRED;
        lastAck = new HelloAck(moduleEphRaw, moduleRandom, module.moduleId(),
                module.pairedTerminal(), module.keyEpoch(), module.seqHighWater(),
                module.serviceMode(), status, sig);

        LinkSession session = LinkSession.establish(LinkSession.Role.DISPENSER, ephemeral,
                com.bank.atmsecure.crypto.X25519.fromRawPublic(hello.terminalEphemeralPublic()),
                transcript);
        this.session = session;
        module.openSession(session.sessionId(), session.channelBinding());
        if (trace != null) {
            trace.accept("DISPENSER: handshake " + Long.toUnsignedString(session.sessionId())
                    + " status=" + status);
        }
        byte[] ackBytes = lastAck.encode();
        link.transmit(ackBytes);
        return ackBytes;
    }

    /** Opens a sealed request frame and dispatches it to the module; returns the sealed result. */
    public byte[] process(byte[] requestFrameBytes) {
        if (session == null) {
            throw new ProtoException("no session");
        }
        WireFrame frame = WireFrame.decodeHeader(requestFrameBytes);
        byte[] pt = session.open(frame);
        if (frame.type() != MessageType.DISPENSE) {
            throw new ProtoException("unexpected message type " + frame.type());
        }
        DispenseRequest request = DispenseRequest.decode(pt);
        DispenseResult result = module.dispense(request);
        if (trace != null) {
            trace.accept("DISPENSER: " + result);
        }
        WireFrame out = session.seal(MessageType.DISPENSE_RESULT, result.encode());
        byte[] bytes = out.encode();
        link.transmit(bytes);
        return bytes;
    }

    public CashDispenserModule module() {
        return module;
    }

    public LinkSession session() {
        return session;
    }

    public void resetSession() {
        this.session = null;
        this.lastAck = null;
    }

    public HelloAck lastAck() {
        return lastAck;
    }
}
