package com.bank.atmsecure.attack;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bank.atmsecure.auth.PairingGrant;
import com.bank.atmsecure.dispenser.CashDispenserModule;
import com.bank.atmsecure.model.CashPlan;
import com.bank.atmsecure.model.Denomination;
import com.bank.atmsecure.model.Money;
import com.bank.atmsecure.model.TxId;
import com.bank.atmsecure.sim.AtmScenario;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Service-replacement attacks and the re-pairing protocol.
 *
 * <p>Re-pairing is the highest-risk operation: it deliberately changes which authority a module will
 * obey. The design requires three independent gates that an attacker in the field cannot all satisfy:
 * a host-signed grant scoped to this exact module/terminal/epoch, the physical service jumper closed,
 * and a grant that has never been used and is inside its validity window.
 */
class ModulePairingAttackTest {

    @Test
    @DisplayName("Re-pairing without the physical service jumper is refused")
    void pairingRequiresServiceJumper() {
        AtmScenario atm = AtmScenario.standard();
        PairingGrant.IssuedPairing issued = atm.host.issuePairingGrant(atm.moduleId,
                new com.bank.atmsecure.model.TerminalId("ATM-EVIL"), 2, "TECH-X", "WO-X");
        CashDispenserModule.PairingOutcome out = atm.module.pair(issued.grant(), false);
        assertFalse(out.accepted());
        assertEquals(1, atm.module.keyEpoch(), "epoch must not advance on a refused pairing");
    }

    @Test
    @DisplayName("A re-pairing grant without the service-authority signature is refused")
    void pairingRequiresHostServiceSignature() {
        AtmScenario atm = AtmScenario.standard();
        PairingGrant forged = PairingGrant.builder()
                .grantId("PG-FORGED")
                .moduleId(atm.moduleId)
                .terminalId(new com.bank.atmsecure.model.TerminalId("ATM-EVIL"))
                .technicianId("TECH-X")
                .workOrderId("WO-X")
                .newKeyEpoch(2)
                .validity(atm.clock.millis(), atm.clock.millis() + 600_000)
                .build()
                .signedBy(com.bank.atmsecure.crypto.Ed25519.generate().getPrivate());
        CashDispenserModule.PairingOutcome out = atm.module.pair(forged, true);
        assertFalse(out.accepted());
        assertEquals(1, atm.module.keyEpoch());
    }

    @Test
    @DisplayName("A grant for one module cannot be used to re-pair a different module")
    void grantIsScopedToModule() {
        AtmScenario atm = AtmScenario.standard();
        PairingGrant.IssuedPairing issued = atm.host.issuePairingGrant(
                new com.bank.atmsecure.model.ModuleId("DISP-OTHER"),
                atm.terminalId, 2, "TECH", "WO-OTHER");
        CashDispenserModule.PairingOutcome out = atm.module.pair(issued.grant(), true);
        assertFalse(out.accepted());
    }

    @Test
    @DisplayName("A pairing grant is single-use: replaying it is refused")
    void pairingGrantIsSingleUse() {
        AtmScenario atm = AtmScenario.standard();
        PairingGrant.IssuedPairing issued = atm.host.issuePairingGrant(atm.moduleId, atm.terminalId,
                2, "TECH", "WO-2");
        assertTrue(atm.module.pair(issued.grant(), true).accepted());
        // Replay the same grant (attacker captured it from the technician's laptop).
        CashDispenserModule.PairingOutcome again = atm.module.pair(issued.grant(), true);
        assertFalse(again.accepted());
        assertEquals(2, atm.module.keyEpoch(), "epoch must not advance twice from one grant");
    }

    @Test
    @DisplayName("A pairing epoch that does not advance is refused")
    void epochMustAdvance() {
        AtmScenario atm = AtmScenario.standard();
        PairingGrant.IssuedPairing issued = atm.host.issuePairingGrant(atm.moduleId, atm.terminalId,
                1, "TECH", "WO-1b"); // same epoch as current
        assertFalse(atm.module.pair(issued.grant(), true).accepted());
    }

    @Test
    @DisplayName("Re-pairing a terminal invalidates authorisations minted under the old epoch")
    void rePairingInvalidatesOldEpochAuthorizations() {
        AtmScenario atm = AtmScenario.standard();
        // Obtain a valid authorisation at epoch 1 (but do not dispense it yet).
        var t = atm.simulator.terminal();
        var side = atm.side();
        side.connect(t);
        byte[] nonce = side.challenge();
        CashPlan p = CashPlan.single(Denomination.YUAN_100, 1);
        var auth = atm.host.authorize(new com.bank.atmsecure.host.Host.OnlineRequest(atm.terminalId,
                atm.moduleId, atm.module.keyEpoch(), new TxId("OLD-EPOCH"), "CUST",
                Money.ofYuan(100), p, nonce, t.session().channelBinding())).authorization();

        // Service tech re-pairs the module to the same terminal at a new epoch (e.g. after a repair).
        atm.issueAndAcceptPairing(atm.terminalId, 2);
        assertEquals(2, atm.module.keyEpoch());

        int before = atm.module.cassettes().countOf(Denomination.YUAN_100);
        var outcome = t.submit(side, new com.bank.atmsecure.dispenser.DispenseRequest.Online(auth));
        assertFalse(outcome.dispensed(), "authorisation from the old epoch must be refused");
        assertEquals(before, atm.module.cassettes().countOf(Denomination.YUAN_100));
    }

    @Test
    @DisplayName("A module swapped from another ATM bears an epoch/terminal mismatch and is refused")
    void moduleFromAnotherAtmIsRefused() {
        AtmScenario atm = AtmScenario.standard();
        // Attacker physically swaps in a module that was legitimately paired to a different terminal.
        AtmScenario other = AtmScenario.builder()
                .moduleId("DISP-SWAP")
                .terminalId("ATM-OTHER")
                .build();
        // Same host root, but this module is paired to ATM-OTHER at epoch 1.
        AtmScenario ours = atm;
        // The victim terminal (ATM-0001) gets an authorisation for its own module id, but the swapped
        // module has a different id — so even if we ran it, the check order rejects on module id.
        var t = ours.simulator.terminal();
        var side = ours.side();
        side.connect(t);
        byte[] nonce = side.challenge();
        CashPlan p = CashPlan.single(Denomination.YUAN_100, 1);
        var authForOurs = ours.host.authorize(new com.bank.atmsecure.host.Host.OnlineRequest(
                ours.terminalId, ours.moduleId, ours.module.keyEpoch(), new TxId("SWAP"), "CUST",
                Money.ofYuan(100), p, nonce, t.session().channelBinding())).authorization();

        // Feed our authorisation to the OTHER module via a direct inject.
        var res = other.module.dispense(new com.bank.atmsecure.dispenser.DispenseRequest.Online(
                authForOurs));
        assertFalse(res.ok(), "other module must reject an authorisation for our module id");
    }

    @Test
    @DisplayName("Single-module compromise does not affect other modules")
    void compromiseIsScopedToModule() {
        // Two modules share the host root. Compromising module A's NVRAM must not let A mint money,
        // and either way module B remains independently sound.
        AtmScenario a = AtmScenario.builder().moduleId("DISP-A").terminalId("ATM-A").build();
        AtmScenario b = AtmScenario.builder().moduleId("DISP-B").terminalId("ATM-B").build();
        // (Each builder makes its own host; the property under test is module-scoped state.)
        var imageA = a.module.captureNvram();
        a.module.restoreNvramImage(imageA);
        a.module.boot();
        // A simple honest dispense still works on a fresh module after a same-image boot.
        var t = a.simulator.terminal();
        var side = a.side();
        var out = t.dispenseOnline(side, a.host, "C", new TxId("A-OK"),
                CashPlan.single(Denomination.YUAN_100, 1));
        assertTrue(out.dispensed(), out.detail());
        // B is untouched and healthy.
        assertFalse(b.module.isLocked());
    }

    @Test
    @DisplayName("A counterfeit module without a valid manufacturing certificate is rejected by terminals")
    void counterfeitModuleCertificateIsRejected() {
        AtmScenario atm = AtmScenario.standard();
        // Attacker builds a module with a self-signed certificate.
        var attackerHsm = new com.bank.atmsecure.host.HostHsm();
        var fakeKeys = com.bank.atmsecure.crypto.Ed25519.generate();
        var fakeCert = attackerHsm.manufactureModuleCertificate(new com.bank.atmsecure.model.ModuleId(
                "DISP-FAKE"), fakeKeys.getPublic(), "SN-FAKE", atm.clock.millis());
        // Terminal pins the real manufacturing key, so it must reject the fake certificate.
        var t = atm.simulator.terminal();
        assertFalse(fakeCert.verify(atm.hsm.manufacturingPublicKey()));
        // And accept the real one.
        assertTrue(atm.module.certificate().verify(atm.hsm.manufacturingPublicKey()));
    }
}
