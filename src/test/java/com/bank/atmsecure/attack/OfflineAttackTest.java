package com.bank.atmsecure.attack;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bank.atmsecure.auth.OfflineEnvelope;
import com.bank.atmsecure.dispenser.DispenseRequest;
import com.bank.atmsecure.host.Host;
import com.bank.atmsecure.link.TerminalEndpoint;
import com.bank.atmsecure.model.CashPlan;
import com.bank.atmsecure.model.Denomination;
import com.bank.atmsecure.model.Money;
import com.bank.atmsecure.model.TxId;
import com.bank.atmsecure.security.NvramStore;
import com.bank.atmsecure.sim.AtmScenario;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Offline-mode attacks. Offline is where a weak module must bound its own spending, because no host is
 * reachable to say yes or no. The design:
 * <ul>
 *   <li>host-signed envelope with <em>absolute</em> cumulative spend/count ceilings and a per-tx cap;</li>
 *   <li>module keeps lifetime cumulative offline spend/count, OTP-anchored and forward-only;</li>
 *   <li>envelope is single-use (id burned) and reconciled with module-signed receipts on reconnect.</li>
 * </ul>
 */
class OfflineAttackTest {

    private static OfflineEnvelope issueStandardEnvelope(AtmScenario atm) {
        return atm.host.issueOfflineEnvelope(new Host.OfflineIssueRequest(
                atm.moduleId, atm.terminalId, atm.module.keyEpoch(),
                Money.ofYuan(3000), Money.ofYuan(1000), 3, 10));
    }

    @Test
    @DisplayName("Honest offline dispenses work up to the envelope, then stop")
    void offlineDispenseRespectsEnvelope() {
        AtmScenario atm = AtmScenario.standard();
        OfflineEnvelope env = issueStandardEnvelope(atm);
        assertTrue(atm.module.loadOfflineEnvelope(env));

        CashPlan p = CashPlan.single(Denomination.YUAN_100, 5); // 500 each
        var t = atm.simulator.terminal();
        var side = atm.side();

        for (int i = 0; i < 3; i++) {
            t.resetSession();
            atm.simulator.dispenser().resetSession();
            TerminalEndpoint.Outcome out = t.dispenseOffline(side, env, p);
            assertTrue(out.dispensed(), "offline dispense " + i + ": " + out.detail());
        }
        // Fourth is over the count cap (3).
        t.resetSession();
        atm.simulator.dispenser().resetSession();
        TerminalEndpoint.Outcome fourth = t.dispenseOffline(side, env, p);
        assertFalse(fourth.dispensed(), "must refuse past the transaction count cap");
        assertEquals(Money.ofYuan(1500).cents(), atm.module.offlineSpentCumulative());
        assertEquals(3, atm.module.offlineCountCumulative());
    }

    @Test
    @DisplayName("Offline per-transaction cap is enforced")
    void offlinePerTxCapEnforced() {
        AtmScenario atm = AtmScenario.standard();
        OfflineEnvelope env = issueStandardEnvelope(atm);
        assertTrue(atm.module.loadOfflineEnvelope(env));
        var t = atm.simulator.terminal();
        var side = atm.side();
        // 1200 exceeds the 1000 per-tx cap.
        TerminalEndpoint.Outcome out = t.dispenseOffline(side, env,
                CashPlan.single(Denomination.YUAN_100, 12));
        assertFalse(out.dispensed());
    }

    @Test
    @DisplayName("Negative offline amount is rejected (no reverse-dispense arithmetic tricks)")
    void negativeAmountRejected() {
        AtmScenario atm = AtmScenario.standard();
        // CashPlan cannot be negative by construction; this documents the invariant.
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> CashPlan.parse("100x-5"));
    }

    @Test
    @DisplayName("Replaying an offline envelope after reloading it is refused (id burned)")
    void replayedEnvelopeRefused() {
        AtmScenario atm = AtmScenario.standard();
        OfflineEnvelope env = issueStandardEnvelope(atm);
        assertTrue(atm.module.loadOfflineEnvelope(env));
        // Use it fully.
        var t = atm.simulator.terminal();
        var side = atm.side();
        t.dispenseOffline(side, env, CashPlan.single(Denomination.YUAN_100, 1));
        // Attacker tries to load the same envelope again to reset the budget.
        assertFalse(atm.module.loadOfflineEnvelope(env), "a used envelope id must not reload");
    }

    @Test
    @DisplayName("Attacker-crafted envelope (no host signature) is refused")
    void forgedEnvelopeRefused() {
        AtmScenario atm = AtmScenario.standard();
        OfflineEnvelope forged = OfflineEnvelope.builder()
                .envelopeId("ENV-EVIL")
                .moduleId(atm.moduleId)
                .terminalId(atm.terminalId)
                .keyEpoch(atm.module.keyEpoch())
                .perTxMax(Money.ofYuan(5000))
                .spendCapCents(Long.MAX_VALUE / 2)
                .txCountCap(1_000_000)
                .grantedBudget(Money.ofYuan(3000))
                .grantedTransactions(3)
                .seqWindow(1, 10)
                .validity(atm.clock.millis(), atm.clock.millis() + 3_600_000)
                .build()
                .signedBy(com.bank.atmsecure.crypto.Ed25519.generate().getPrivate());
        assertFalse(atm.module.loadOfflineEnvelope(forged));
    }

    @Test
    @DisplayName("THE key offline attack: restore NVRAM to 'un-spend' the offline budget")
    void nvramRollbackCannotRefillOfflineBudget() {
        AtmScenario atm = AtmScenario.standard();
        OfflineEnvelope env = issueStandardEnvelope(atm);
        assertTrue(atm.module.loadOfflineEnvelope(env));
        var t = atm.simulator.terminal();
        var side = atm.side();
        CashPlan p = CashPlan.single(Denomination.YUAN_100, 5); // 500

        // Attacker snapshots the module's NVRAM before any spending.
        NvramStore.NvramImage preSpend = atm.module.captureNvram();

        // Spend twice.
        for (int i = 0; i < 2; i++) {
            t.resetSession();
            atm.simulator.dispenser().resetSession();
            assertTrue(t.dispenseOffline(side, env, p).dispensed());
        }
        long spentAfterTwo = atm.module.offlineSpentCumulative();
        assertEquals(Money.ofYuan(1000).cents(), spentAfterTwo);

        // Restore the pre-spend image and reboot, as a chip-off attacker would.
        atm.module.restoreNvramImage(preSpend);
        atm.module.boot();

        // The OTP-anchored cumulative spend cannot be rewound. Either the module keeps the anchor
        // (and so refuses further spending) or it locks outright.
        assertTrue(atm.module.isLocked()
                        || atm.module.offlineSpentCumulative() >= Money.ofYuan(1000).cents(),
                "rollback must not lower the cumulative offline spend");

        // Attempt to spend again within the replayed envelope; must be refused.
        t.resetSession();
        atm.simulator.dispenser().resetSession();
        TerminalEndpoint.Outcome third = t.dispenseOffline(side, env, p);
        assertFalse(third.dispensed(),
                "after a rollback the module must not dispense past the original envelope");
    }

    @Test
    @DisplayName("Rollback below the OTP floor after a spend locks the module")
    void rollbackBelowOtpFloorLocksModule() {
        AtmScenario atm = AtmScenario.standard();
        OfflineEnvelope env = issueStandardEnvelope(atm);
        assertTrue(atm.module.loadOfflineEnvelope(env));
        NvramStore.NvramImage before = atm.module.captureNvram();
        var t = atm.simulator.terminal();
        var side = atm.side();
        assertTrue(t.dispenseOffline(side, env, CashPlan.single(Denomination.YUAN_100, 5))
                .dispensed());

        atm.module.restoreNvramImage(before);
        atm.module.boot();
        assertTrue(atm.module.isLocked(), "restoring an image below the OTP floor must lock the "
                + "module: " + atm.module.lockReason());
        assertFalse(atm.module.dispense(new DispenseRequest.Offline(env,
                CashPlan.single(Denomination.YUAN_100, 1))).ok());
    }

    @Test
    @DisplayName("Torn write during a dispense leaves the previous good state")
    void tornWriteDoesNotCorruptOrGrantExtraCash() {
        AtmScenario atm = AtmScenario.standard();
        OfflineEnvelope env = issueStandardEnvelope(atm);
        assertTrue(atm.module.loadOfflineEnvelope(env));
        var t = atm.simulator.terminal();
        var side = atm.side();
        atm.module.injectTornWrite();
        TerminalEndpoint.Outcome out = t.dispenseOffline(side, env,
                CashPlan.single(Denomination.YUAN_100, 5));
        assertTrue(out.dispensed(), "a torn write must not break an otherwise valid dispense");
        atm.module.boot();
        assertEquals(1, atm.module.offlineCountCumulative());
    }

    @Test
    @DisplayName("Offline receipts reconcile with the host and are usable as settlement evidence")
    void offlineReceiptsReconcile() {
        AtmScenario atm = AtmScenario.standard();
        OfflineEnvelope env = issueStandardEnvelope(atm);
        assertTrue(atm.module.loadOfflineEnvelope(env));
        var t = atm.simulator.terminal();
        var side = atm.side();
        var r1 = t.dispenseOffline(side, env, CashPlan.single(Denomination.YUAN_100, 2));
        t.resetSession();
        atm.simulator.dispenser().resetSession();
        var r2 = t.dispenseOffline(side, env, CashPlan.single(Denomination.YUAN_100, 3));
        assertTrue(r1.dispensed() && r2.dispensed());

        // Connectivity restored: the terminal hands the receipts to the host.
        Host.ReconciliationResult rr = atm.host.reconcile(atm.moduleId,
                java.util.List.of(r1.receipt(), r2.receipt()));
        assertEquals(2, rr.accepted());
        assertEquals(0, rr.rejected());
        // A replayed receipt is caught.
        Host.ReconciliationResult again = atm.host.reconcile(atm.moduleId,
                java.util.List.of(r1.receipt()));
        assertEquals(1, again.rejected());
    }
}
