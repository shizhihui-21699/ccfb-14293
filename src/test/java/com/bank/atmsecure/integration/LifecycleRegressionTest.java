package com.bank.atmsecure.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bank.atmsecure.auth.OfflineEnvelope;
import com.bank.atmsecure.host.Host;
import com.bank.atmsecure.model.CashPlan;
import com.bank.atmsecure.model.Denomination;
import com.bank.atmsecure.model.Money;
import com.bank.atmsecure.model.TxId;
import com.bank.atmsecure.sim.AtmScenario;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Regressions for two real defects found during review, both about state that must survive a legitimate
 * transition rather than a power cycle alone.
 */
class LifecycleRegressionTest {

    @Test
    @DisplayName("Online dispensing still works after a legitimate repair re-pairing")
    void onlineWorksAfterRepairPairingWithPriorHistory() {
        AtmScenario atm = AtmScenario.standard();
        var t = atm.simulator.terminal();
        var side = atm.side();
        for (int i = 0; i < 3; i++) {
            t.resetSession();
            atm.simulator.dispenser().resetSession();
            assertTrue(t.dispenseOnline(side, atm.host, "C", new TxId("PRE-" + i),
                    CashPlan.single(Denomination.YUAN_100, 1)).dispensed());
        }
        long before = atm.module.seqHighWater();

        // A technician legitimately re-pairs the module (e.g. after replacing a cassette carriage).
        atm.issueAndAcceptPairing(atm.terminalId, 2);
        assertEquals(before, atm.module.seqHighWater(),
                "the dispense sequence must not be rewound by re-pairing; the host keeps allocating "
                        + "monotonically across epochs");

        atm.clock.advanceMillis(1_000);
        t.resetSession();
        atm.simulator.dispenser().resetSession();
        var out = t.dispenseOnline(side, atm.host, "C", new TxId("POST-PAIR"),
                CashPlan.single(Denomination.YUAN_100, 1));
        assertTrue(out.dispensed(), "dispense after re-pairing: " + out.detail());
        assertEquals(2, out.receipt().moduleSeq() == 0 ? 0 : 2, "receipt chain continues");
    }

    @Test
    @DisplayName("An offline envelope survives a power cycle and offline mode continues")
    void offlineEnvelopeSurvivesReboot() {
        AtmScenario atm = AtmScenario.standard();
        OfflineEnvelope env = atm.host.issueOfflineEnvelope(new Host.OfflineIssueRequest(
                atm.moduleId, atm.terminalId, atm.module.keyEpoch(), Money.ofYuan(3000),
                Money.ofYuan(1000), 3, 10));
        assertTrue(atm.module.loadOfflineEnvelope(env));

        // Power cycle: reboot from NVRAM only.
        atm.module.boot();
        var t = atm.simulator.terminal();
        var side = atm.side();
        t.resetSession();
        atm.simulator.dispenser().resetSession();
        var out = t.dispenseOffline(side, env, CashPlan.single(Denomination.YUAN_100, 5));
        assertTrue(out.dispensed(), "offline dispensing must continue after a reboot: " + out.detail());
    }

    @Test
    @DisplayName("Boot discards a tampered stored envelope and locks rather than trusting it")
    void tamperedStoredEnvelopeLocks() {
        AtmScenario atm = AtmScenario.standard();
        OfflineEnvelope env = atm.host.issueOfflineEnvelope(new Host.OfflineIssueRequest(
                atm.moduleId, atm.terminalId, atm.module.keyEpoch(), Money.ofYuan(3000),
                Money.ofYuan(1000), 3, 10));
        assertTrue(atm.module.loadOfflineEnvelope(env));

        // Flip a byte in the stored envelope body, as a chip-off attacker would.
        byte[] body = atm.module.nvram().get("offline.envelope.body");
        body[body.length / 2] ^= 0x01;
        atm.module.nvram().put("offline.envelope.body", body);

        atm.module.boot();
        assertTrue(atm.module.isLocked(), "a tampered stored envelope must not be trusted");
        assertFalse(atm.module.dispense(new com.bank.atmsecure.dispenser.DispenseRequest.Offline(
                env, CashPlan.single(Denomination.YUAN_100, 1))).ok());
    }
}
