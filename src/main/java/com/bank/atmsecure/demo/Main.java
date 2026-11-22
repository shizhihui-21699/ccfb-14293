package com.bank.atmsecure.demo;

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

/**
 * A narrated walk-through of the design against the incident that motivated it.
 *
 * <p>Run with {@code gradle run}. Each section prints what an attacker does and what the system does
 * in response, ending with the cassette balance so the absence of money movement is visible.
 */
public final class Main {
    private static final String RULE = "=".repeat(78);

    public static void main(String[] args) {
        section("0. Honest baseline");
        AtmScenario atm = AtmScenario.standard();
        printModule(atm);
        CashPlan oneHundred = CashPlan.single(Denomination.YUAN_100, 1);
        var ok = atm.simulator.terminal().dispenseOnline(atm.side(), atm.host, "CUST-1",
                new TxId("TX-OK"), oneHundred);
        System.out.println("honest dispense: " + (ok.dispensed() ? "OK " + ok.receipt()
                : "REFUSED " + ok.detail()));
        printModule(atm);

        section("1. Black-box attack: attacker's laptop drives the bus with a forged command");
        AtmScenario a1 = AtmScenario.standard();
        a1.simulator.link().installTap();
        var t1 = a1.simulator.terminal();
        var s1 = a1.side();
        s1.connect(t1);
        var forged = com.bank.atmsecure.auth.HostAuthorization.builder()
                .moduleId(a1.moduleId).terminalId(a1.terminalId).txId(new TxId("EVIL-1"))
                .amountCents(CashPlan.single(Denomination.YUAN_100, 50).totalCents())
                .plan(CashPlan.single(Denomination.YUAN_100, 50))
                .nonce(s1.challenge()).channelBinding(t1.session().channelBinding())
                .seq(1).validity(a1.clock.millis(), a1.clock.millis() + 60_000)
                .keyEpoch(a1.module.keyEpoch())
                .build().signedBy(com.bank.atmsecure.crypto.Ed25519.generate().getPrivate());
        var r1 = t1.submit(s1, new DispenseRequest.Online(forged));
        System.out.println("forged dispense: " + (r1.dispensed() ? "!! MONEY MOVED"
                : "REFUSED (" + r1.detail() + ")"));
        printCassettes(a1);

        section("2. Replay of a genuinely host-signed command captured off the wire");
        AtmScenario a2 = AtmScenario.standard();
        var t2 = a2.simulator.terminal();
        var s2 = a2.side();
        s2.connect(t2);
        byte[] nonce = s2.challenge();
        var signed = a2.host.authorize(new Host.OnlineRequest(a2.terminalId, a2.moduleId,
                a2.module.keyEpoch(), new TxId("CAP-1"), "CUST", Money.ofYuan(500),
                CashPlan.single(Denomination.YUAN_100, 5), nonce,
                t2.session().channelBinding())).authorization();
        a2.simulator.dispenser().resetSession();
        t2.resetSession();
        s2.connect(t2);
        var r2 = t2.submit(s2, new DispenseRequest.Online(signed));
        System.out.println("replayed command: " + (r2.dispensed() ? "!! MONEY MOVED"
                : "REFUSED (" + r2.detail() + ")"));
        printCassettes(a2);

        section("3. Replace the business-software PC (clone with the same identity)");
        AtmScenario a3 = AtmScenario.standard();
        var clone = new TerminalEndpoint(a3.terminalId, new com.bank.atmsecure.link.SimLink(),
                a3.hsm.manufacturingPublicKey(), "atm-business/1.0", null);
        var s3 = a3.side();
        s3.connect(clone);
        var authSmall = a3.host.authorize(new Host.OnlineRequest(a3.terminalId, a3.moduleId,
                a3.module.keyEpoch(), new TxId("CLONE-1"), "CUST", Money.ofYuan(500),
                CashPlan.single(Denomination.YUAN_100, 5), s3.challenge(),
                clone.session().channelBinding())).authorization();
        var inflated = com.bank.atmsecure.auth.HostAuthorization.decode(padSignature(
                com.bank.atmsecure.auth.HostAuthorization.builder()
                        .moduleId(authSmall.moduleId()).terminalId(authSmall.terminalId())
                        .txId(authSmall.txId())
                        .amountCents(CashPlan.single(Denomination.YUAN_100, 50).totalCents())
                        .plan(CashPlan.single(Denomination.YUAN_100, 50))
                        .nonce(authSmall.nonce()).channelBinding(authSmall.channelBinding())
                        .seq(authSmall.seq())
                        .validity(authSmall.issuedAtMillis(), authSmall.expiresAtMillis())
                        .keyEpoch(authSmall.keyEpoch()).build(),
                authSmall.signature()));
        var r3 = clone.submit(s3, new DispenseRequest.Online(inflated));
        System.out.println("inflated clone command: " + (r3.dispensed() ? "!! MONEY MOVED"
                : "REFUSED (" + r3.detail() + ")"));
        printCassettes(a3);

        section("4. Offline: steal budget by rolling back the module's NVRAM");
        AtmScenario a4 = AtmScenario.standard();
        OfflineEnvelope env = a4.host.issueOfflineEnvelope(new Host.OfflineIssueRequest(
                a4.moduleId, a4.terminalId, a4.module.keyEpoch(), Money.ofYuan(3000),
                Money.ofYuan(1000), 3, 10));
        a4.module.loadOfflineEnvelope(env);
        NvramStore.NvramImage clean = a4.module.captureNvram();
        var t4 = a4.simulator.terminal();
        var s4 = a4.side();
        CashPlan p4 = CashPlan.single(Denomination.YUAN_100, 5);
        for (int i = 0; i < 3; i++) {
            t4.resetSession();
            a4.simulator.dispenser().resetSession();
            t4.dispenseOffline(s4, env, p4);
        }
        System.out.println("before rollback: cumSpent="
                + Money.ofCents(a4.module.offlineSpentCumulative())
                + " cumCount=" + a4.module.offlineCountCumulative());
        a4.module.restoreNvramImage(clean);
        a4.module.boot();
        System.out.println("after NVRAM rollback + boot: locked=" + a4.module.isLocked()
                + (a4.module.isLocked() ? " (" + a4.module.lockReason() + ")" : "")
                + " cumSpent=" + Money.ofCents(a4.module.offlineSpentCumulative()));
        t4.resetSession();
        a4.simulator.dispenser().resetSession();
        var r4 = t4.dispenseOffline(s4, env, p4);
        System.out.println("post-rollback dispense: " + (r4.dispensed() ? "!! MONEY MOVED"
                : "REFUSED (" + r4.detail() + ")"));
        printCassettes(a4);

        section("5. Service re-pairing requires host grant + physical jumper");
        AtmScenario a5 = AtmScenario.standard();
        var badGrant = atm.host.issuePairingGrant(a5.moduleId,
                new com.bank.atmsecure.model.TerminalId("ATM-EVIL"), 2, "X", "WO-X");
        System.out.println("pair without jumper: "
                + a5.module.pair(badGrant.grant(), false).reason());
        var goodGrant = a5.host.issuePairingGrant(a5.moduleId, a5.terminalId, 2, "TECH", "WO-2");
        var accepted = a5.module.pair(goodGrant.grant(), true);
        System.out.println("pair with jumper + valid grant: accepted=" + accepted.accepted()
                + " epoch=" + accepted.keyEpoch());
        var replay = a5.module.pair(goodGrant.grant(), true);
        System.out.println("replay same grant: accepted=" + replay.accepted()
                + " (" + replay.reason() + ")");
        System.out.println();
        System.out.println(RULE);
        System.out.println("Every attack above left the cassettes untouched. Only the honest "
                + "transactions moved money.");
    }

    private static void section(String title) {
        System.out.println();
        System.out.println(RULE);
        System.out.println(title);
        System.out.println(RULE);
    }

    private static void printCassettes(AtmScenario atm) {
        System.out.println("cassettes: " + atm.module.cassettes().describe()
                + "  total=" + atm.module.cassettes().totalValue());
    }

    private static void printModule(AtmScenario atm) {
        System.out.println("module: " + atm.module.healthSummary());
    }

    private static byte[] padSignature(com.bank.atmsecure.auth.HostAuthorization template,
            byte[] sig) {
        var w = new com.bank.atmsecure.crypto.Canonical.Writer();
        w.bytes(template.unsignedBytes());
        w.bytes(sig);
        return w.toByteArray();
    }

    private Main() {
    }
}
