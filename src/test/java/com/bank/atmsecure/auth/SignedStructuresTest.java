package com.bank.atmsecure.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bank.atmsecure.crypto.Ed25519;
import com.bank.atmsecure.model.CashPlan;
import com.bank.atmsecure.model.Denomination;
import com.bank.atmsecure.model.ModuleId;
import com.bank.atmsecure.model.Money;
import com.bank.atmsecure.model.TerminalId;
import com.bank.atmsecure.model.TxId;
import java.security.KeyPair;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Round-trip, tamper-resistance and domain-separation tests for the signed structures. */
class SignedStructuresTest {
    private static final ModuleId MOD = new ModuleId("DISP-001");
    private static final TerminalId TERM = new TerminalId("ATM-0001");

    private HostAuthorization sample(KeyPair host) {
        CashPlan plan = CashPlan.builder().add(Denomination.YUAN_100, 2)
                .add(Denomination.YUAN_50, 1).build();
        return HostAuthorization.builder()
                .moduleId(MOD).terminalId(TERM).txId(new TxId("TX-1"))
                .amount(Money.ofCents(plan.totalCents())).plan(plan)
                .nonce(new byte[16]).channelBinding(new byte[32])
                .seq(5).validity(1000, 61_000).keyEpoch(1)
                .build().signedBy(host.getPrivate());
    }

    @Test
    @DisplayName("HostAuthorization encodes, decodes and verifies")
    void authorizationRoundTrip() {
        KeyPair host = Ed25519.generate();
        HostAuthorization a = sample(host);
        assertTrue(a.verifySignature(host.getPublic()));
        HostAuthorization back = HostAuthorization.decode(a.encode());
        assertEquals(a, back);
        assertEquals(a.seq(), back.seq());
        assertTrue(back.verifySignature(host.getPublic()));
    }

    @Test
    @DisplayName("Every signed field is covered: changing any one breaks verification")
    void authorizationFieldBinding() {
        KeyPair host = Ed25519.generate();
        HostAuthorization base = sample(host);
        CashPlan bigger = CashPlan.single(Denomination.YUAN_100, 3);
        HostAuthorization changedPlan = HostAuthorization.builder()
                .moduleId(base.moduleId()).terminalId(base.terminalId()).txId(base.txId())
                .amountCents(bigger.totalCents()).plan(bigger)
                .nonce(base.nonce()).channelBinding(base.channelBinding())
                .seq(base.seq()).validity(base.issuedAtMillis(), base.expiresAtMillis())
                .keyEpoch(base.keyEpoch())
                .build();
        assertFalse(changedPlan.verifySignature(host.getPublic()),
                "amount/plan must be signature-bound");

        HostAuthorization changedSeq = HostAuthorization.builder()
                .moduleId(base.moduleId()).terminalId(base.terminalId()).txId(base.txId())
                .amountCents(base.amountCents()).plan(base.plan())
                .nonce(base.nonce()).channelBinding(base.channelBinding())
                .seq(base.seq() + 1).validity(base.issuedAtMillis(), base.expiresAtMillis())
                .keyEpoch(base.keyEpoch())
                .build();
        assertFalse(changedSeq.verifySignature(host.getPublic()), "sequence must be bound");

        HostAuthorization changedEpoch = HostAuthorization.builder()
                .moduleId(base.moduleId()).terminalId(base.terminalId()).txId(base.txId())
                .amountCents(base.amountCents()).plan(base.plan())
                .nonce(base.nonce()).channelBinding(base.channelBinding())
                .seq(base.seq()).validity(base.issuedAtMillis(), base.expiresAtMillis())
                .keyEpoch(base.keyEpoch() + 1)
                .build();
        assertFalse(changedEpoch.verifySignature(host.getPublic()), "epoch must be bound");
    }

    @Test
    @DisplayName("Domain separation: an authorization signature is not valid as an envelope signature")
    void domainSeparation() {
        KeyPair host = Ed25519.generate();
        HostAuthorization a = sample(host);
        // A signature over the authorization body cannot be re-used for an envelope with the same
        // claimed fields — the domains differ.
        OfflineEnvelope env = OfflineEnvelope.builder()
                .envelopeId("E1").moduleId(MOD).terminalId(TERM).keyEpoch(1)
                .perTxMax(Money.ofYuan(1000)).spendCapCents(Money.ofYuan(3000).cents())
                .txCountCap(3).seqWindow(1, 10).grantedBudget(Money.ofYuan(3000))
                .grantedTransactions(3).validity(1000, 61_000)
                .build();
        assertFalse(Ed25519.verify(host.getPublic(), env.unsignedBytes(), a.signature()));
    }

    @Test
    @DisplayName("Authorization builder refuses amount/plan mismatch")
    void builderRejectsInconsistentAmount() {
        CashPlan plan = CashPlan.single(Denomination.YUAN_100, 1);
        assertThrows(IllegalArgumentException.class, () -> HostAuthorization.builder()
                .moduleId(MOD).terminalId(TERM).txId(new TxId("TX-BAD"))
                .amountCents(plan.totalCents() + 1).plan(plan)
                .nonce(new byte[16]).channelBinding(new byte[32])
                .seq(1).validity(0, 1000).keyEpoch(1).build());
    }

    @Test
    @DisplayName("Decoding a truncated or trailing-byte structure fails")
    void decodeStrictness() {
        KeyPair host = Ed25519.generate();
        byte[] enc = sample(host).encode();
        assertThrows(RuntimeException.class,
                () -> HostAuthorization.decode(java.util.Arrays.copyOf(enc, enc.length - 1)));
        byte[] padded = java.util.Arrays.copyOf(enc, enc.length + 1);
        assertThrows(RuntimeException.class, () -> HostAuthorization.decode(padded));
    }

    @Test
    @DisplayName("Module certificate and pairing grant verify and are domain-separated")
    void certificateAndGrant() {
        KeyPair manufacturing = Ed25519.generate();
        KeyPair service = Ed25519.generate();
        KeyPair module = Ed25519.generate();
        ModuleCertificate cert = ModuleCertificate.issue(manufacturing.getPrivate(), MOD,
                module.getPublic(), "SN-1", 1000);
        assertTrue(cert.verify(manufacturing.getPublic()));
        assertFalse(cert.verify(service.getPublic()));
        ModuleCertificate back = ModuleCertificate.decode(cert.encode());
        assertTrue(back.verify(manufacturing.getPublic()));
        assertEquals(MOD, back.moduleId());

        PairingGrant grant = PairingGrant.builder().grantId("G1").moduleId(MOD).terminalId(TERM)
                .technicianId("T").workOrderId("W").newKeyEpoch(2).validity(1000, 2000)
                .build().signedBy(service.getPrivate());
        assertTrue(grant.verifySignature(service.getPublic()));
        assertFalse(grant.verifySignature(manufacturing.getPublic()));
    }
}
