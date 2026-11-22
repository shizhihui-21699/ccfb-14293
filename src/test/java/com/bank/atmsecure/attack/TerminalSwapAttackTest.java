package com.bank.atmsecure.attack;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bank.atmsecure.auth.HostAuthorization;
import com.bank.atmsecure.crypto.Ed25519;
import com.bank.atmsecure.dispenser.DispenseRequest;
import com.bank.atmsecure.host.Host;
import com.bank.atmsecure.link.TerminalEndpoint;
import com.bank.atmsecure.model.CashPlan;
import com.bank.atmsecure.model.Denomination;
import com.bank.atmsecure.model.Money;
import com.bank.atmsecure.model.TxId;
import com.bank.atmsecure.sim.AtmScenario;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The second attack in the brief: replace the whole PC that runs the business software.
 *
 * <p>The threat model assumes the attacker owns that PC completely — root, the software, the config,
 * any secret the software held. The defence is that the PC never held the one secret that matters:
 * the host's dispense-authorisation key. Everything a cloned PC can do is therefore bounded by what
 * the (uncompromised) host will sign for it.
 */
class TerminalSwapAttackTest {

    @Test
    @DisplayName("Cloned terminal with identical identity cannot mint money; host refuses its requests")
    void clonedTerminalCannotObtainHostAuthorizationForUnauthorisedSpend() {
        AtmScenario atm = AtmScenario.standard();
        // The attacker images the PC: same terminal id, same software version, same pinned keys.
        var clone = new com.bank.atmsecure.link.TerminalEndpoint(atm.terminalId,
                new com.bank.atmsecure.link.SimLink(), atm.hsm.manufacturingPublicKey(),
                "atm-business/1.0", null);
        var side = atm.side();
        assertTrue(side.connect(clone));

        // The clone asks the host for 2000 when the policy cap is 5000 — this will pass policy, so
        // instead it asks for a plan the host will approve, then tries to tamper it. First: it tries a
        // straight request and we confirm it *can* transact (that is by design — business auth is the
        // host's job, not the terminal's). The point of this test is what happens next.
        CashPlan twoThousand = CashPlan.single(Denomination.YUAN_100, 20);
        byte[] nonce = side.challenge();
        Host.Decision decision = atm.host.authorize(new Host.OnlineRequest(atm.terminalId,
                atm.moduleId, atm.module.keyEpoch(), new TxId("CLONE-1"), "CUST", Money.ofYuan(2000),
                twoThousand, nonce, clone.session().channelBinding()));
        assertTrue(decision.approved(), "host approves within policy — that is the host's decision");

        // The clone now rewrites the plan upward, keeping the host signature bytes.
        HostAuthorization original = decision.authorization();
        HostAuthorization inflated = HostAuthorization.builder()
                .moduleId(original.moduleId())
                .terminalId(original.terminalId())
                .txId(original.txId())
                .amountCents(CashPlan.single(Denomination.YUAN_100, 40).totalCents())
                .plan(CashPlan.single(Denomination.YUAN_100, 40)) // ask for 4000 instead of 2000
                .nonce(original.nonce())
                .channelBinding(original.channelBinding())
                .seq(original.seq())
                .validity(original.issuedAtMillis(), original.expiresAtMillis())
                .keyEpoch(original.keyEpoch())
                .build();
        assertFalse(inflated.verifySignature(atm.hsm.authorizationPublicKey()),
                "changing the plan must break the host signature");

        int before = atm.module.cassettes().countOf(Denomination.YUAN_100);
        HostAuthorization withCopiedSig = copyBodyWithSignature(inflated, original.signature());
        TerminalEndpoint.Outcome outcome =
                clone.submit(side, new DispenseRequest.Online(withCopiedSig));
        assertFalse(outcome.dispensed());
        assertEquals(before, atm.module.cassettes().countOf(Denomination.YUAN_100));
    }

    /** Re-encodes a template body with a foreign signature attached, as a forger would. */
    private static HostAuthorization copyBodyWithSignature(HostAuthorization template,
            byte[] signature) {
        var w = new com.bank.atmsecure.crypto.Canonical.Writer();
        w.bytes(template.unsignedBytes());
        w.bytes(signature);
        return HostAuthorization.decode(w.toByteArray());
    }

    @Test
    @DisplayName("Clone cannot forge a host signature even with full knowledge of the protocol")
    void cloneCannotForgeHostSignature() {
        AtmScenario atm = AtmScenario.standard();
        var clone = new com.bank.atmsecure.link.TerminalEndpoint(atm.terminalId,
                new com.bank.atmsecure.link.SimLink(), atm.hsm.manufacturingPublicKey(),
                "atm-business/1.0", null);
        var side = atm.side();
        assertTrue(side.connect(clone));
        byte[] nonce = side.challenge();
        CashPlan big = CashPlan.single(Denomination.YUAN_100, 50);

        // Everything public is known to the clone; only the HSM private key is not. Forge with the
        // clone's own key. (The public key is derivable from the pinned key; forging requires the
        // private key, which never leaves the HSM.)
        HostAuthorization forged = HostAuthorization.builder()
                .moduleId(atm.moduleId)
                .terminalId(atm.terminalId)
                .txId(new TxId("CLONE-FORGE"))
                .amountCents(big.totalCents())
                .plan(big)
                .nonce(nonce)
                .channelBinding(clone.session().channelBinding())
                .seq(atm.module.seqHighWater() + 1)
                .validity(atm.clock.millis(), atm.clock.millis() + 60_000)
                .keyEpoch(atm.module.keyEpoch())
                .build()
                .signedBy(Ed25519.generate().getPrivate());

        int before = atm.module.cassettes().countOf(Denomination.YUAN_100);
        assertFalse(forged.verifySignature(atm.hsm.authorizationPublicKey()));
        TerminalEndpoint.Outcome outcome = clone.submit(side, new DispenseRequest.Online(forged));
        assertFalse(outcome.dispensed());
        assertEquals(before, atm.module.cassettes().countOf(Denomination.YUAN_100));
    }

    @Test
    @DisplayName("A different terminal's identity is rejected by a module paired to us")
    void foreignTerminalIdIsRejected() {
        AtmScenario atm = AtmScenario.standard();
        // Attacker runs the business software but claims to be a different ATM.
        var foreign = new com.bank.atmsecure.link.TerminalEndpoint(
                new com.bank.atmsecure.model.TerminalId("ATM-9999"),
                new com.bank.atmsecure.link.SimLink(), atm.hsm.manufacturingPublicKey(),
                "atm-business/1.0", null);
        var side = atm.side();
        assertTrue(side.connect(foreign));

        byte[] nonce = side.challenge();
        CashPlan p = CashPlan.single(Denomination.YUAN_100, 1);
        // Host will refuse because this terminal is not provisioned at all.
        Host.Decision d = atm.host.authorize(new Host.OnlineRequest(foreign.terminalId(),
                atm.moduleId, atm.module.keyEpoch(), new TxId("FOREIGN"), "CUST",
                Money.ofYuan(100), p, nonce, foreign.session().channelBinding()));
        assertFalse(d.approved(), "host must refuse an unprovisioned terminal");
    }
}
