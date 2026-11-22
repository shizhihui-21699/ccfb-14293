package com.bank.atmsecure.attack;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bank.atmsecure.auth.DispenseReceipt;
import com.bank.atmsecure.auth.HostAuthorization;
import com.bank.atmsecure.crypto.Ed25519;
import com.bank.atmsecure.crypto.Kdf;
import com.bank.atmsecure.dispenser.DispenseRequest;
import com.bank.atmsecure.dispenser.DispenseStatus;
import com.bank.atmsecure.link.DispenserEndpoint;
import com.bank.atmsecure.link.TerminalEndpoint;
import com.bank.atmsecure.model.CashPlan;
import com.bank.atmsecure.model.Denomination;
import com.bank.atmsecure.model.TxId;
import com.bank.atmsecure.sim.AtmScenario;
import com.bank.atmsecure.wire.MessageType;
import com.bank.atmsecure.wire.ProtoException;
import com.bank.atmsecure.wire.WireFrame;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The black-box attack from the incident report: an attacker physically splices their own computer
 * onto the dispenser's data line and drives the protocol themselves.
 *
 * <p>Each test models one capability such a box would have, and asserts the module refuses to move
 * cash. None of these tests may reach into module internals to "help" the attacker — the attacker only
 * gets the bytes on the wire and the documented bus interface, exactly like a real splice.
 */
class BlackBoxBusAttackTest {

    private static CashPlan plan() {
        return CashPlan.single(Denomination.YUAN_100, 5);
    }

    @Test
    @DisplayName("Attacker's box speaks the protocol with no host signature at all")
    void forgedAuthorizationWithoutHostSignatureIsRejected() {
        AtmScenario atm = AtmScenario.standard();
        var t = atm.simulator.terminal();
        var side = atm.side();
        side.connect(t);
        byte[] nonce = side.challenge();

        // Build a perfectly well-formed authorisation — but sign it with the attacker's own key.
        var attackerKey = Ed25519.generate().getPrivate();
        HostAuthorization forged = HostAuthorization.builder()
                .moduleId(atm.moduleId)
                .terminalId(atm.terminalId)
                .txId(new TxId("ATTACK-1"))
                .amount(com.bank.atmsecure.model.Money.ofYuan(500))
                .plan(plan())
                .nonce(nonce)
                .channelBinding(t.session().channelBinding())
                .seq(999)
                .validity(atm.clock.millis(), atm.clock.millis() + 60_000)
                .keyEpoch(atm.module.keyEpoch())
                .build()
                .signedBy(attackerKey);

        int before = atm.module.cassettes().countOf(Denomination.YUAN_100);
        TerminalEndpoint.Outcome outcome =
                t.submit(side, new DispenseRequest.Online(forged));
        assertFalse(outcome.dispensed());
        assertEquals(before, atm.module.cassettes().countOf(Denomination.YUAN_100),
                "no notes may leave the cassette for a forged authorisation");
    }

    @Test
    @DisplayName("Attacker replays a previously captured, genuinely host-signed dispense")
    void replayedGenuineAuthorizationIsRejected() {
        AtmScenario atm = AtmScenario.standard();
        var t = atm.simulator.terminal();
        var side = atm.side();

        // Capture one honest, host-signed authorisation by tapping the bus.
        atm.simulator.link().installTap();
        hostSignedAuthorization capture = captureSignedAuthorization(atm, t, side);

        // Now the attacker replays the exact bytes in a brand-new session.
        t.resetSession();
        atm.simulator.dispenser().resetSession();
        side.connect(t);
        int before = atm.module.cassettes().countOf(Denomination.YUAN_100);
        TerminalEndpoint.Outcome replay =
                t.submit(side, new DispenseRequest.Online(capture.authorization));
        assertFalse(replay.dispensed(), "replayed authorisation must be refused");
        assertEquals(before, atm.module.cassettes().countOf(Denomination.YUAN_100));
        assertTrue(atm.module.audit().recent().stream()
                .anyMatch(e -> e.kind() == com.bank.atmsecure.security.AuditChain.Kind.NONCE_REJECTED
                        || e.kind() == com.bank.atmsecure.security.AuditChain.Kind.AUTH_REJECTED
                        || e.kind() == com.bank.atmsecure.security.AuditChain.Kind.SEQ_REJECTED));
    }

    @Test
    @DisplayName("Attacker flips a byte in a valid sealed frame (bit-flip / active MITM)")
    void tamperedCiphertextIsRejectedBeforeReachingChecks() {
        AtmScenario atm = AtmScenario.standard();
        var t = atm.simulator.terminal();
        var side = atm.side();
        side.connect(t);

        byte[] nonce = side.challenge();
        HostAuthorization auth = atm.host.authorize(new com.bank.atmsecure.host.Host.OnlineRequest(
                atm.terminalId, atm.moduleId, atm.module.keyEpoch(), new TxId("TX-FLIP"),
                "CUST", com.bank.atmsecure.model.Money.ofYuan(500), plan(), nonce,
                t.session().channelBinding())).authorization();

        byte[] frame = t.transmit(new DispenseRequest.Online(auth));
        int before = atm.module.cassettes().countOf(Denomination.YUAN_100);
        // Flip a ciphertext byte (past the header).
        byte[] corrupted = frame.clone();
        corrupted[frame.length - 5] ^= 0x01;
        assertThrows(ProtoException.class, () -> atm.simulator.dispenser().process(corrupted));
        assertEquals(before, atm.module.cassettes().countOf(Denomination.YUAN_100));
    }

    @Test
    @DisplayName("Attacker flips the message-type byte in the header (header is AEAD-bound)")
    void tamperedHeaderIsRejected() {
        AtmScenario atm = AtmScenario.standard();
        var t = atm.simulator.terminal();
        var side = atm.side();
        side.connect(t);

        byte[] nonce = side.challenge();
        HostAuthorization auth = atm.host.authorize(new com.bank.atmsecure.host.Host.OnlineRequest(
                atm.terminalId, atm.moduleId, atm.module.keyEpoch(), new TxId("TX-HDR"), "CUST",
                com.bank.atmsecure.model.Money.ofYuan(500), plan(), nonce,
                t.session().channelBinding())).authorization();

        byte[] frame = t.transmit(new DispenseRequest.Online(auth));
        // Header layout: magic(4) ver(2) type(1) session(8) seq(8); type is at offset 6.
        byte[] corrupted = frame.clone();
        corrupted[6] = (byte) MessageType.STATUS.code();
        assertThrows(ProtoException.class, () -> atm.simulator.dispenser().process(corrupted));
    }

    @Test
    @DisplayName("Attacker sends an oversized / truncated / garbage frame")
    void malformedFramesAreDropped() {
        AtmScenario atm = AtmScenario.standard();
        var t = atm.simulator.terminal();
        var side = atm.side();
        side.connect(t);

        assertThrows(ProtoException.class,
                () -> atm.simulator.dispenser().process(new byte[] {1, 2, 3}));
        byte[] huge = new byte[com.bank.atmsecure.model.Protocol.MAX_FRAME_BYTES + 1];
        assertThrows(ProtoException.class,
                () -> atm.simulator.dispenser().process(huge));
        byte[] garbage = new byte[200];
        new java.security.SecureRandom().nextBytes(garbage);
        assertThrows(ProtoException.class,
                () -> atm.simulator.dispenser().process(garbage));
    }

    @Test
    @DisplayName("Attacker opens their own parallel session and swaps frames between sessions")
    void crossSessionFrameSwapIsRejected() {
        AtmScenario atm = AtmScenario.standard();
        var t1 = atm.simulator.terminal();
        var side = atm.side();
        side.connect(t1);
        byte[] frameSession1 = t1.session().seal(MessageType.STATUS, new byte[] {0}).encode();

        // New session (reconnect), then deliver session 1's frame.
        t1.resetSession();
        atm.simulator.dispenser().resetSession();
        side.connect(t1);
        assertThrows(ProtoException.class, () -> atm.simulator.dispenser().process(frameSession1));
    }

    @Test
    @DisplayName("Attacker bypasses the terminal entirely and speaks raw frames to the dispenser")
    void handRolledFramesWithoutSessionKeyAreRejected() {
        AtmScenario atm = AtmScenario.standard();
        // Attacker builds a frame with a random key, correct framing, and a forged payload.
        byte[] randomKey = new byte[32];
        new java.security.SecureRandom().nextBytes(randomKey);
        HostAuthorization forged = HostAuthorization.builder()
                .moduleId(atm.moduleId)
                .terminalId(atm.terminalId)
                .txId(new TxId("RAW-1"))
                .amount(com.bank.atmsecure.model.Money.ofYuan(500))
                .plan(plan())
                .nonce(new byte[16])
                .channelBinding(new byte[32])
                .seq(500)
                .validity(atm.clock.millis(), atm.clock.millis() + 60_000)
                .keyEpoch(1)
                .build()
                .signedBy(Ed25519.generate().getPrivate());
        WireFrame f = WireFrame.create(randomKey, MessageType.DISPENSE, 12345L, 1,
                new DispenseRequest.Online(forged).encode());
        int before = atm.module.cassettes().countOf(Denomination.YUAN_100);
        assertThrows(ProtoException.class,
                () -> atm.simulator.dispenser().process(f.encode()));
        assertEquals(before, atm.module.cassettes().countOf(Denomination.YUAN_100));
    }

    @Test
    @DisplayName("Attacker swaps the module id inside a genuine authorisation")
    void relabelledModuleIdIsRejected() {
        AtmScenario atm = AtmScenario.standard();
        var t = atm.simulator.terminal();
        var side = atm.side();
        side.connect(t);
        byte[] nonce = side.challenge();
        byte[] binding = t.session().channelBinding();
        HostAuthorization good = atm.host.authorize(new com.bank.atmsecure.host.Host.OnlineRequest(
                atm.terminalId, atm.moduleId, atm.module.keyEpoch(), new TxId("TX-REL"),
                "CUST", com.bank.atmsecure.model.Money.ofYuan(500), plan(), nonce, binding))
                .authorization();

        // Re-encode with a different module id, which invalidates the signature.
        HostAuthorization relabelled = HostAuthorization.builder()
                .moduleId(new com.bank.atmsecure.model.ModuleId("DISP-999"))
                .terminalId(good.terminalId())
                .txId(good.txId())
                .amountCents(good.amountCents())
                .plan(good.plan())
                .nonce(good.nonce())
                .channelBinding(good.channelBinding())
                .seq(good.seq())
                .validity(good.issuedAtMillis(), good.expiresAtMillis())
                .keyEpoch(good.keyEpoch())
                .build();
        // Even if the attacker copies the signature bytes across, verification must fail.
        HostAuthorization withCopiedSig = copySignature(relabelled, good.signature());
        assertFalse(withCopiedSig.verifySignature(atm.hsm.authorizationPublicKey()));

        TerminalEndpoint.Outcome outcome = t.submit(side, new DispenseRequest.Online(withCopiedSig));
        assertFalse(outcome.dispensed());
    }

    @Test
    @DisplayName("Attackers' captured traffic reveals no dispense authorisation in the clear")
    void tappedTrafficContainsNoPlaintextAuthorization() {
        AtmScenario atm = AtmScenario.standard();
        var t = atm.simulator.terminal();
        var side = atm.side();
        atm.simulator.link().installTap();
        side.connect(t);
        TerminalEndpoint.Outcome ok = t.dispenseOnline(side, atm.host, "CUST", new TxId("TX-TAP"),
                plan());
        assertTrue(ok.dispensed());

        byte[] needle = "TX-TAP".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        for (byte[] record : atm.simulator.link().observed()) {
            assertFalse(indexOf(record, needle) >= 0,
                    "plaintext transaction id must not appear on the tapped bus");
        }
    }

    private static int indexOf(byte[] hay, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= hay.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private record hostSignedAuthorization(HostAuthorization authorization) {
    }

    private hostSignedAuthorization captureSignedAuthorization(AtmScenario atm, TerminalEndpoint t,
            com.bank.atmsecure.link.Simulator.DispenserSide side) {
        side.connect(t);
        byte[] nonce = side.challenge();
        HostAuthorization auth = atm.host.authorize(new com.bank.atmsecure.host.Host.OnlineRequest(
                atm.terminalId, atm.moduleId, atm.module.keyEpoch(), new TxId("TX-CAP"), "CUST",
                com.bank.atmsecure.model.Money.ofYuan(500), plan(), nonce,
                t.session().channelBinding())).authorization();
        return new hostSignedAuthorization(auth);
    }

    private static HostAuthorization copySignature(HostAuthorization template, byte[] signature) {
        try {
            // Build through decode so the signature field is accepted verbatim, then re-decode.
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            com.bank.atmsecure.crypto.Canonical.Writer w =
                    new com.bank.atmsecure.crypto.Canonical.Writer();
            w.bytes(template.unsignedBytes());
            w.bytes(signature);
            return HostAuthorization.decode(w.toByteArray());
        } catch (RuntimeException e) {
            throw e;
        }
    }
}
