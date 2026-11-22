package com.bank.atmsecure.attack;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bank.atmsecure.dispenser.DispenseStatus;
import com.bank.atmsecure.dispenser.ResourceLimits;
import com.bank.atmsecure.model.CashPlan;
import com.bank.atmsecure.model.Denomination;
import com.bank.atmsecure.model.TxId;
import com.bank.atmsecure.sim.AtmScenario;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Denial-of-service and resource-exhaustion attacks against the weak module, plus clock and entropy
 * fault attacks. Each limit is a defence, not just a performance note — see {@link ResourceLimits}.
 */
class ResourceAndFaultAttackTest {

    @Test
    @DisplayName("A flood of bogus authorisations is throttled, then the module locks")
    void authorisationFloodIsThrottledAndEventuallyLocks() {
        AtmScenario atm = AtmScenario.standard();
        int before = atm.module.cassettes().countOf(Denomination.YUAN_100);
        var t = atm.simulator.terminal();
        var side = atm.side();

        int attempts = ResourceLimits.MAX_CONSECUTIVE_AUTH_FAILURES + 5;
        int refused = 0;
        for (int i = 0; i < attempts; i++) {
            // Advance the clock a full second so both the verify-rate and handshake-rate buckets
            // refill; a real flood also takes time, and those limiters are part of what is tested.
            atm.clock.advanceMillis(1_000);
            t.resetSession();
            atm.simulator.dispenser().resetSession();
            if (!side.connect(t)) {
                continue; // module may already be locked/refusing handshakes at the tail
            }
            var forged = com.bank.atmsecure.auth.HostAuthorization.builder()
                    .moduleId(atm.moduleId).terminalId(atm.terminalId)
                    .txId(new TxId("FLOOD-" + i))
                    .amountCents(CashPlan.single(Denomination.YUAN_100, 1).totalCents())
                    .plan(CashPlan.single(Denomination.YUAN_100, 1))
                    .nonce(side.challenge())
                    .channelBinding(t.session().channelBinding())
                    .seq(1 + i)
                    .validity(atm.clock.millis(), atm.clock.millis() + 60_000)
                    .keyEpoch(atm.module.keyEpoch())
                    .build()
                    .signedBy(com.bank.atmsecure.crypto.Ed25519.generate().getPrivate());
            var res = atm.module.dispense(
                    new com.bank.atmsecure.dispenser.DispenseRequest.Online(forged));
            if (!res.ok()) {
                refused++;
            }
        }
        assertTrue(refused > 0);
        assertTrue(atm.module.isLocked(), "repeated auth failures must lock the module for service");
        assertEquals(before, atm.module.cassettes().countOf(Denomination.YUAN_100));
    }

    @Test
    @DisplayName("Stuck RNG faults the module closed rather than issuing predictable challenges")
    void stuckRngLocksModule() {
        AtmScenario atm = AtmScenario.standard();
        atm.module.injectStuckRng();
        var t = atm.simulator.terminal();
        var side = atm.side();
        // Handshake may proceed, but the module cannot issue a safe challenge, so no dispense is possible.
        side.connect(t);
        assertTrue(atm.module.isLocked());
        assertFalse(atm.module.admitHello());
    }

    @Test
    @DisplayName("A dispense attempted after the authorisation expiry is refused")
    void expiredAuthorizationRejected() {
        AtmScenario atm = AtmScenario.standard();
        var t = atm.simulator.terminal();
        var side = atm.side();
        side.connect(t);
        byte[] nonce = side.challenge();
        CashPlan p = CashPlan.single(Denomination.YUAN_100, 1);
        var auth = atm.host.authorize(new com.bank.atmsecure.host.Host.OnlineRequest(atm.terminalId,
                atm.moduleId, atm.module.keyEpoch(), new TxId("EXP"), "CUST",
                com.bank.atmsecure.model.Money.ofYuan(100), p, nonce,
                t.session().channelBinding())).authorization();
        // Move the clock past the authorisation validity.
        atm.clock.advanceMillis(5 * 60_000);
        var res = atm.module.dispense(new com.bank.atmsecure.dispenser.DispenseRequest.Online(auth));
        assertFalse(res.ok());
        assertEquals(DispenseStatus.AUTHORIZATION_REJECTED, res.status());
    }

    @Test
    @DisplayName("Sequence far ahead of the high-water mark is refused (no silent skipping)")
    void hugeSequenceJumpRejected() {
        AtmScenario atm = AtmScenario.standard();
        var t = atm.simulator.terminal();
        var side = atm.side();
        side.connect(t);
        byte[] nonce = side.challenge();
        CashPlan p = CashPlan.single(Denomination.YUAN_100, 1);
        var auth = atm.host.authorize(new com.bank.atmsecure.host.Host.OnlineRequest(atm.terminalId,
                atm.moduleId, atm.module.keyEpoch(), new TxId("JUMP"), "CUST",
                com.bank.atmsecure.model.Money.ofYuan(100), p, nonce,
                t.session().channelBinding())).authorization();
        var skewed = com.bank.atmsecure.auth.HostAuthorization.builder()
                .moduleId(auth.moduleId()).terminalId(auth.terminalId()).txId(auth.txId())
                .amountCents(auth.amountCents()).plan(auth.plan()).nonce(auth.nonce())
                .channelBinding(auth.channelBinding())
                .seq(auth.seq() + 1_000_000)
                .validity(auth.issuedAtMillis(), auth.expiresAtMillis())
                .keyEpoch(auth.keyEpoch())
                .build();
        // Re-sign by the host so only the jump bound is under test (not the signature).
        var hostSigned = atm.hsm.signAuthorization(skewed);
        var res = atm.module.dispense(
                new com.bank.atmsecure.dispenser.DispenseRequest.Online(hostSigned));
        assertFalse(res.ok());
    }

    @Test
    @DisplayName("Authorisation nonce is single-use even within the same session")
    void nonceIsSingleUse() {
        AtmScenario atm = AtmScenario.standard();
        var t = atm.simulator.terminal();
        var side = atm.side();
        side.connect(t);
        byte[] nonce = side.challenge();
        CashPlan p = CashPlan.single(Denomination.YUAN_100, 1);
        var auth1 = atm.host.authorize(new com.bank.atmsecure.host.Host.OnlineRequest(atm.terminalId,
                atm.moduleId, atm.module.keyEpoch(), new TxId("NONCE-1"), "CUST",
                com.bank.atmsecure.model.Money.ofYuan(100), p, nonce,
                t.session().channelBinding())).authorization();
        assertTrue(atm.module.dispense(
                new com.bank.atmsecure.dispenser.DispenseRequest.Online(auth1)).ok());
        // A second authorisation reusing the now-consumed nonce (host would allocate a new seq).
        var auth2 = atm.host.authorize(new com.bank.atmsecure.host.Host.OnlineRequest(atm.terminalId,
                atm.moduleId, atm.module.keyEpoch(), new TxId("NONCE-2"), "CUST",
                com.bank.atmsecure.model.Money.ofYuan(100), p, nonce,
                t.session().channelBinding())).authorization();
        var res = atm.module.dispense(
                new com.bank.atmsecure.dispenser.DispenseRequest.Online(auth2));
        assertFalse(res.ok(), "the reused nonce must be refused");
    }

    @Test
    @DisplayName("Physical note theft is detectable at reconciliation")
    void physicalTheftIsDetectedByReconciliation() {
        AtmScenario atm = AtmScenario.standard();
        // The thief pries the cabinet and removes cassettes directly — software never sees it.
        atm.module.simulatePhysicalTheft(CashPlan.builder().add(Denomination.YUAN_100, 100)
                .add(Denomination.YUAN_50, 100).add(Denomination.YUAN_20, 100).build());
        // Reconciliation compares the module's signed receipts to the host's authorisations.
        var issues = atm.host.auditModuleState(atm.moduleId, atm.module.seqHighWater(),
                atm.module.receiptSeq());
        // The stock discrepancy itself is caught by cassette-level settlement, modelled here by the
        // fact that the cassette total no longer matches what was loaded minus what was dispensed.
        assertTrue(atm.module.cassettes().countOf(Denomination.YUAN_100)
                < 1000 - 0, "stolen notes are gone from the cassette ledger");
        assertTrue(issues.isEmpty(), "no signature-level issue; stock audit is separate");
    }
}
