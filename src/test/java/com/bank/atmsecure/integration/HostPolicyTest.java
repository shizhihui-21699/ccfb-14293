package com.bank.atmsecure.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bank.atmsecure.host.Host;
import com.bank.atmsecure.host.HostPolicy;
import com.bank.atmsecure.model.CashPlan;
import com.bank.atmsecure.model.Denomination;
import com.bank.atmsecure.model.Money;
import com.bank.atmsecure.model.TxId;
import com.bank.atmsecure.sim.AtmScenario;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Host-side business rules and cross-cutting invariants on the honest path. */
class HostPolicyTest {

    @Test
    @DisplayName("Host refuses amounts above the per-transaction cap")
    void perTransactionLimit() {
        AtmScenario atm = AtmScenario.standard();
        CashPlan tooBig = CashPlan.single(Denomination.YUAN_100, 60); // 6000 > 5000 cap
        Host.Decision d = atm.host.authorize(new Host.OnlineRequest(atm.terminalId, atm.moduleId,
                atm.module.keyEpoch(), new TxId("LIMIT-1"), "CUST", Money.ofYuan(6000), tooBig,
                new byte[16], new byte[32]));
        assertFalse(d.approved());
        assertTrue(d.reason().contains("limit"));
    }

    @Test
    @DisplayName("Host refuses a plan whose total disagrees with the claimed amount")
    void amountPlanMismatch() {
        AtmScenario atm = AtmScenario.standard();
        CashPlan plan = CashPlan.single(Denomination.YUAN_100, 1);
        Host.Decision d = atm.host.authorize(new Host.OnlineRequest(atm.terminalId, atm.moduleId,
                atm.module.keyEpoch(), new TxId("MISMATCH"), "CUST", Money.ofYuan(200), plan,
                new byte[16], new byte[32]));
        assertFalse(d.approved());
    }

    @Test
    @DisplayName("Host refuses an unprovisioned module")
    void unprovisionedModule() {
        AtmScenario atm = AtmScenario.standard();
        var other = new com.bank.atmsecure.model.ModuleId("DISP-GHOST");
        Host.Decision d = atm.host.authorize(new Host.OnlineRequest(atm.terminalId, other, 1,
                new TxId("GHOST"), "CUST", Money.ofYuan(100),
                CashPlan.single(Denomination.YUAN_100, 1), new byte[16], new byte[32]));
        assertFalse(d.approved());
    }

    @Test
    @DisplayName("Host allocates strictly increasing sequence numbers per module")
    void sequenceMonotone() {
        AtmScenario atm = AtmScenario.standard();
        long a = atm.ledger.nextSequence(atm.moduleId);
        long b = atm.ledger.nextSequence(atm.moduleId);
        assertEquals(a + 1, b);
    }

    @Test
    @DisplayName("Daily limit blocks the transaction that would cross it")
    void dailyLimit() {
        AtmScenario atm = AtmScenario.standard();
        // Each 500; cap 20000/day means 40 transactions. Do a few and check accounting is live.
        CashPlan p = CashPlan.single(Denomination.YUAN_100, 5);
        for (int i = 0; i < 3; i++) {
            var d = atm.host.authorize(new Host.OnlineRequest(atm.terminalId, atm.moduleId,
                    atm.module.keyEpoch(), new TxId("DAY-" + i), "CUST", Money.ofYuan(500), p,
                    new byte[16], new byte[32]));
            assertTrue(d.approved(), d.reason());
        }
        long epochDay = atm.clock.millis() / 86_400_000L;
        HostPolicy.DailyKey key = new HostPolicy.DailyKey(atm.terminalId, "CUST", epochDay);
        assertEquals(Money.ofYuan(1500).cents(), atm.ledger.spentToday(key).cents());
    }

    @Test
    @DisplayName("The HSM is the only signer and counts every signing operation")
    void hsmSigningIsCounted() {
        AtmScenario atm = AtmScenario.standard();
        long before = atm.hsm.signatureCount();
        atm.host.authorize(new Host.OnlineRequest(atm.terminalId, atm.moduleId,
                atm.module.keyEpoch(), new TxId("HSM-1"), "CUST", Money.ofYuan(100),
                CashPlan.single(Denomination.YUAN_100, 1), new byte[16], new byte[32]));
        assertEquals(before + 1, atm.hsm.signatureCount());
    }
}
