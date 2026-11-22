package com.bank.atmsecure.attack;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bank.atmsecure.auth.OfflineEnvelope;
import com.bank.atmsecure.host.Host;
import com.bank.atmsecure.model.CashPlan;
import com.bank.atmsecure.model.Denomination;
import com.bank.atmsecure.model.Money;
import com.bank.atmsecure.model.TxId;
import com.bank.atmsecure.security.NvramStore;
import com.bank.atmsecure.sim.AtmScenario;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Crash-consistency: a power loss at any point in a dispense must not permanently brick the module, and
 * must never grant extra cash. The ordering is persist-NVRAM → burn-OTP → move-cash, so the invariant
 * {@code NVRAM >= OTP floor} holds on every honest power cut and a boot that sees otherwise can only
 * mean an attacker rewound NVRAM.
 */
class CrashConsistencyTest {

    @Test
    @DisplayName("Power loss with the pre-dispense NVRAM image leaves the module serviceable")
    void powerLossBeforeAnchorDoesNotBrick() {
        AtmScenario atm = AtmScenario.standard();
        var t = atm.simulator.terminal();
        var side = atm.side();
        // One honest dispense to get some history, then snapshot NVRAM right after it committed.
        assertTrue(t.dispenseOnline(side, atm.host, "C", new TxId("CRASH-1"),
                CashPlan.single(Denomination.YUAN_100, 1)).dispensed());
        NvramStore.NvramImage image = atm.module.captureNvram();
        byte[] anchorTip = atm.module.nvram().get("audit.tip");

        // Power cut: reboot from the committed image. This is NOT a rollback below the OTP floor
        // (the anchor was burned after this image was committed only for the *next* dispense), so the
        // module must come back healthy, not locked.
        atm.module.restoreNvramImage(image);
        atm.module.boot();
        assertFalse(atm.module.isLocked(), "an honest power cycle must not brick the module: "
                + atm.module.lockReason());

        // And it can still dispense.
        atm.clock.advanceMillis(1_000);
        t.resetSession();
        atm.simulator.dispenser().resetSession();
        assertTrue(t.dispenseOnline(side, atm.host, "C", new TxId("CRASH-2"),
                CashPlan.single(Denomination.YUAN_100, 1)).dispensed());
    }

    @Test
    @DisplayName("Offline cumulative spend never exceeds its envelope across a crash window")
    void offlineCrashNeverOverSpends() {
        AtmScenario atm = AtmScenario.standard();
        OfflineEnvelope env = atm.host.issueOfflineEnvelope(new Host.OfflineIssueRequest(
                atm.moduleId, atm.terminalId, atm.module.keyEpoch(), Money.ofYuan(3000),
                Money.ofYuan(1000), 3, 10));
        assertTrue(atm.module.loadOfflineEnvelope(env));
        var t = atm.simulator.terminal();
        var side = atm.side();
        CashPlan p = CashPlan.single(Denomination.YUAN_100, 5);

        for (int i = 0; i < 3; i++) {
            t.resetSession();
            atm.simulator.dispenser().resetSession();
            assertTrue(t.dispenseOffline(side, env, p).dispensed());
        }
        long spent = atm.module.offlineSpentCumulative();
        assertTrue(spent <= env.spendCapCents(),
                "cumulative spend " + spent + " must never exceed cap " + env.spendCapCents());

        // A reboot after the last commit must keep the cumulative spend (no refill).
        atm.module.boot();
        assertTrue(atm.module.offlineSpentCumulative() >= spent);

        // A further offline dispense is refused on both caps.
        t.resetSession();
        atm.simulator.dispenser().resetSession();
        assertFalse(t.dispenseOffline(side, env, p).dispensed());
    }
}
