package com.bank.atmsecure.attack;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bank.atmsecure.crypto.Ed25519;
import com.bank.atmsecure.link.TerminalEndpoint;
import com.bank.atmsecure.model.CashPlan;
import com.bank.atmsecure.model.Denomination;
import com.bank.atmsecure.model.Money;
import com.bank.atmsecure.model.TxId;
import com.bank.atmsecure.security.NvramStore;
import com.bank.atmsecure.sim.AtmScenario;
import com.bank.atmsecure.wire.Hello;
import com.bank.atmsecure.wire.HelloAck;
import com.bank.atmsecure.wire.LinkSession;
import com.bank.atmsecure.wire.MessageType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Impersonation and protocol-level replay attacks, plus sequence/rollback interplay.
 *
 * <p>Two endpoints must each authenticate the other on the right basis: the terminal authenticates the
 * dispenser via its manufacturing certificate; the dispenser authorises money via the host signature.
 * Neither trusts the other's mere asserted identity.
 */
class ImpersonationAndReplayAttackTest {

    @Test
    @DisplayName("Terminal refuses a counterfeit dispenser that cannot produce a certified signature")
    void terminalRejectsCounterfeitDispenser() {
        AtmScenario atm = AtmScenario.standard();
        // A fake dispenser builds its own keypair and a self-signed certificate; the terminal pins the
        // real manufacturing key and must reject it.
        var fakeHsm = new com.bank.atmsecure.host.HostHsm();
        var fakeKeys = Ed25519.generate();
        var fakeCert = fakeHsm.manufactureModuleCertificate(atm.moduleId, fakeKeys.getPublic(),
                "SN-FAKE", atm.clock.millis());

        var t = atm.simulator.terminal();
        byte[] helloBytes = t.hello();
        Hello hello = Hello.decode(helloBytes);
        // Fake dispenser answers with a valid-looking HELLO_ACK signed by *its own* key.
        byte[] fakeEph = com.bank.atmsecure.crypto.X25519.rawPublic(
                com.bank.atmsecure.crypto.X25519.generate().getPublic());
        byte[] fakeRandom = new byte[32];
        new java.security.SecureRandom().nextBytes(fakeRandom);
        byte[] transcript = com.bank.atmsecure.wire.Handshake.transcript(
                hello.terminalEphemeralPublic(), fakeEph, hello.terminalRandom(), fakeRandom,
                atm.moduleId.value().getBytes(java.nio.charset.StandardCharsets.UTF_8),
                atm.module.keyEpoch());
        byte[] fakeSig = Ed25519.sign(fakeKeys.getPrivate(), transcript);
        HelloAck fakeAck = new HelloAck(fakeEph, fakeRandom, atm.moduleId, atm.terminalId,
                atm.module.keyEpoch(), 0, false, HelloAck.STATUS_OK, fakeSig);

        // The terminal's pinned certificate is the REAL module's. So even though the fake's own cert
        // verifies under its own key, the terminal will not accept a cert it did not pin.
        assertThrows(com.bank.atmsecure.wire.ProtoException.class,
                () -> t.acceptHelloAck(fakeAck.encode(), atm.module.certificate()),
                "a dispenser whose HELLO_ACK is not signed by the certified key must be rejected");
        // Sanity: the fake's certificate does not chain to the pinned manufacturing key.
        assertFalse(fakeCert.verify(atm.hsm.manufacturingPublicKey()));
    }

    @Test
    @DisplayName("Link layer rejects a replayed sealed frame (and a reflected frame)")
    void linkRejectsReplayedFrame() {
        // Build a matched pair of sessions the way the handshake does, so we can exercise the link
        // layer's sequence and direction checks without the module in the way.
        var termKeys = com.bank.atmsecure.crypto.X25519.generate();
        var dispKeys = com.bank.atmsecure.crypto.X25519.generate();
        byte[] termPub = com.bank.atmsecure.crypto.X25519.rawPublic(termKeys.getPublic());
        byte[] dispPub = com.bank.atmsecure.crypto.X25519.rawPublic(dispKeys.getPublic());
        byte[] rnd = new byte[32];
        new java.security.SecureRandom().nextBytes(rnd);
        byte[] transcript = com.bank.atmsecure.wire.Handshake.transcript(termPub, dispPub, rnd, rnd,
                "DISP-001".getBytes(java.nio.charset.StandardCharsets.UTF_8), 1);
        LinkSession term = LinkSession.establish(LinkSession.Role.TERMINAL, termKeys,
                dispKeys.getPublic(), transcript);
        LinkSession disp = LinkSession.establish(LinkSession.Role.DISPENSER, dispKeys,
                termKeys.getPublic(), transcript);

        byte[] frame = term.seal(MessageType.STATUS, new byte[] {1, 2, 3}).encode();
        // First delivery is accepted and consumes the sequence number.
        disp.open(com.bank.atmsecure.wire.WireFrame.decodeHeader(frame));
        // Replay is refused.
        assertThrows(com.bank.atmsecure.wire.ProtoException.class,
                () -> disp.open(com.bank.atmsecure.wire.WireFrame.decodeHeader(frame)));
        // Reflection: the terminal cannot open its own outbound frame back (direction-separated keys).
        byte[] frame2 = term.seal(MessageType.STATUS, new byte[] {4, 5, 6}).encode();
        assertThrows(com.bank.atmsecure.wire.ProtoException.class,
                () -> term.open(com.bank.atmsecure.wire.WireFrame.decodeHeader(frame2)));
    }

    @Test
    @DisplayName("Restoring NVRAM to replay an old sequence number does not let an old auth through")
    void sequenceHighWaterRollbackDoesNotReplayOldAuthorization() {
        AtmScenario atm = AtmScenario.standard();
        var t = atm.simulator.terminal();
        var side = atm.side();

        // Capture NVRAM before any dispense.
        NvramStore.NvramImage clean = atm.module.captureNvram();

        side.connect(t);
        byte[] nonce1 = side.challenge();
        CashPlan p = CashPlan.single(Denomination.YUAN_100, 1);
        var auth1 = atm.host.authorize(new com.bank.atmsecure.host.Host.OnlineRequest(atm.terminalId,
                atm.moduleId, atm.module.keyEpoch(), new TxId("SEQ-1"), "CUST",
                Money.ofYuan(100), p, nonce1, t.session().channelBinding())).authorization();
        assertTrue(t.submit(side, new com.bank.atmsecure.dispenser.DispenseRequest.Online(auth1))
                .dispensed());

        // Attacker restores NVRAM (which would reset the in-NVRAM high-water to 0) and reboots.
        atm.module.restoreNvramImage(clean);
        atm.module.boot();
        // OTP-anchored sequence means the module either kept the high-water or locked.
        assertTrue(atm.module.isLocked() || atm.module.seqHighWater() >= auth1.seq(),
                "rollback must not rewind the dispense sequence");

        // Replay auth1 (seq 1) in a fresh session: the nonce is gone and the seq is not ahead.
        t.resetSession();
        atm.simulator.dispenser().resetSession();
        int before = atm.module.cassettes().countOf(Denomination.YUAN_100);
        if (side.connect(t)) {
            var replay = t.submit(side,
                    new com.bank.atmsecure.dispenser.DispenseRequest.Online(auth1));
            assertFalse(replay.dispensed());
        }
        assertEquals(before, atm.module.cassettes().countOf(Denomination.YUAN_100));
    }

    @Test
    @DisplayName("An authorisation minted for a different session's channel binding is refused")
    void channelBindingMismatchRejected() {
        AtmScenario atm = AtmScenario.standard();
        var t = atm.simulator.terminal();
        var side = atm.side();
        side.connect(t);
        byte[] nonce = side.challenge();
        byte[] oldBinding = t.session().channelBinding();

        // Reconnect → new session → different channel binding, same module challenge flow.
        t.resetSession();
        atm.simulator.dispenser().resetSession();
        side.connect(t);
        CashPlan p = CashPlan.single(Denomination.YUAN_100, 1);
        var auth = atm.host.authorize(new com.bank.atmsecure.host.Host.OnlineRequest(atm.terminalId,
                atm.moduleId, atm.module.keyEpoch(), new TxId("CB-1"), "CUST",
                Money.ofYuan(100), p, side.challenge(), oldBinding)).authorization();
        var res = t.submit(side, new com.bank.atmsecure.dispenser.DispenseRequest.Online(auth));
        assertFalse(res.dispensed(), "old channel binding must not be accepted in a new session");
    }
}
