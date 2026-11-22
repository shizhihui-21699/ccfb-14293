package com.bank.atmsecure.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bank.atmsecure.link.TerminalEndpoint;
import com.bank.atmsecure.model.CashPlan;
import com.bank.atmsecure.model.Denomination;
import com.bank.atmsecure.model.Money;
import com.bank.atmsecure.model.TxId;
import com.bank.atmsecure.sim.AtmScenario;
import org.junit.jupiter.api.Test;

/** The honest path must work end-to-end; every attack test below is a delta from this. */
class HappyPathTest {

    @Test
    void onlineDispenseMovesExactPlanAndEmitsVerifiableReceipt() {
        AtmScenario atm = AtmScenario.standard();
        CashPlan plan = CashPlan.builder()
                .add(Denomination.YUAN_100, 2)
                .add(Denomination.YUAN_50, 1)
                .build();
        int before100 = atm.module.cassettes().countOf(Denomination.YUAN_100);
        int before50 = atm.module.cassettes().countOf(Denomination.YUAN_50);

        TerminalEndpoint.Outcome outcome = atm.simulator.terminal()
                .dispenseOnline(atm.side(), atm.host, "CUST-42", new TxId("TX-1"), plan);

        assertTrue(outcome.dispensed(), outcome.detail());
        assertNotNull(outcome.receipt());
        assertEquals(plan, outcome.receipt().plan());
        assertEquals(Money.ofYuan(250).cents(), outcome.receipt().amountCents());
        assertEquals(Money.ofYuan(250).cents(), plan.totalCents());
        assertTrue(outcome.receipt().verifySignature(
                com.bank.atmsecure.crypto.Ed25519.fromRawPublic(
                        com.bank.atmsecure.crypto.Ed25519.rawPublic(atm.moduleKeys.getPublic()))));
        assertEquals(before100 - 2, atm.module.cassettes().countOf(Denomination.YUAN_100));
        assertEquals(before50 - 1, atm.module.cassettes().countOf(Denomination.YUAN_50));
    }

    @Test
    void twoSequentialDispensesBothSucceed() {
        AtmScenario atm = AtmScenario.standard();
        var t = atm.simulator.terminal();
        var side = atm.side();
        CashPlan p1 = CashPlan.single(Denomination.YUAN_100, 1);
        CashPlan p2 = CashPlan.single(Denomination.YUAN_100, 3);

        TerminalEndpoint.Outcome a = t.dispenseOnline(side, atm.host, "C1", new TxId("TX-A"), p1);
        // Each dispense needs a fresh session/challenge; reconnect.
        t.resetSession();
        atm.simulator.dispenser().resetSession();
        TerminalEndpoint.Outcome b = t.dispenseOnline(side, atm.host, "C1", new TxId("TX-B"), p2);

        assertTrue(a.dispensed(), a.detail());
        assertTrue(b.dispensed(), b.detail());
        assertEquals(2, b.receipt().moduleSeq());
        assertTrue(java.util.Arrays.equals(b.receipt().prevReceiptHash(), a.receipt().hash()));
    }
}
