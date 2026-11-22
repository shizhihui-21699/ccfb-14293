package com.bank.atmsecure.host;

import com.bank.atmsecure.auth.DispenseReceipt;
import com.bank.atmsecure.auth.HostAuthorization;
import com.bank.atmsecure.auth.ModuleCertificate;
import com.bank.atmsecure.auth.OfflineEnvelope;
import com.bank.atmsecure.auth.PairingGrant;
import com.bank.atmsecure.crypto.CryptoException;
import com.bank.atmsecure.crypto.Kdf;
import com.bank.atmsecure.model.CashPlan;
import com.bank.atmsecure.model.ModuleId;
import com.bank.atmsecure.model.Money;
import com.bank.atmsecure.model.TerminalId;
import com.bank.atmsecure.model.TxId;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Model of the bank's hardware security module. The <b>only</b> component able to sign an
 * authorisation that can move cash, and the only place long-term signing keys exist.
 *
 * <p>Properties modelled:
 * <ul>
 *   <li>Private keys are held internally and never handed out — callers pass a description of what
 *       they want signed, not a key. There is no {@code getSigningKey()}.</li>
 *   <li>Every signature is counted and logged. An abnormal spike (a compromised business layer trying
 *       to mint authorisations in a loop) is visible to the bank, not just to the terminal.</li>
 *   <li>The authorisation key and the manufacturing/service keys are distinct, so compromising the
 *       service workflow cannot mint dispense authorisations, and vice versa.</li>
 * </ul>
 *
 * <p>A production HSM would additionally enforce key-usage policy and rate limits in firmware; those
 * are represented by {@link HostPolicy} below and by the counter exposed here.
 */
public final class HostHsm {
    private final KeyPair authorizationKey;
    private final KeyPair manufacturingKey;
    private final KeyPair serviceKey;
    private final AtomicLong signatureCount = new AtomicLong();
    private final List<String> ledger = new ArrayList<>();

    public HostHsm() {
        this.authorizationKey = com.bank.atmsecure.crypto.Ed25519.generate();
        this.manufacturingKey = com.bank.atmsecure.crypto.Ed25519.generate();
        this.serviceKey = com.bank.atmsecure.crypto.Ed25519.generate();
    }

    public PublicKey authorizationPublicKey() {
        return authorizationKey.getPublic();
    }

    public PublicKey manufacturingPublicKey() {
        return manufacturingKey.getPublic();
    }

    public PublicKey servicePublicKey() {
        return serviceKey.getPublic();
    }

    /** Signs a fully-formed, policy-approved authorisation. The caller cannot supply key material. */
    public HostAuthorization signAuthorization(HostAuthorization template) {
        signatureCount.incrementAndGet();
        ledger.add("AUTH " + template.txId() + " " + template.moduleId() + " "
                + Money.ofCents(template.amountCents()));
        return template.signedBy(authorizationKey.getPrivate());
    }

    public OfflineEnvelope signEnvelope(OfflineEnvelope template) {
        signatureCount.incrementAndGet();
        ledger.add("ENVELOPE " + template.envelopeId() + " " + template.moduleId() + " budget="
                + template.grantedBudget());
        return template.signedBy(authorizationKey.getPrivate());
    }

    public PairingGrant signPairingGrant(PairingGrant template) {
        signatureCount.incrementAndGet();
        ledger.add("PAIR " + template.grantId() + " " + template.moduleId() + "->"
                + template.terminalId() + " epoch=" + template.newKeyEpoch());
        return template.signedBy(serviceKey.getPrivate());
    }

    public ModuleCertificate manufactureModuleCertificate(ModuleId id, PublicKey modulePublicKey,
            String serial, long atMillis) {
        signatureCount.incrementAndGet();
        ledger.add("MANUFACTURE " + id + " serial=" + serial);
        return ModuleCertificate.issue(manufacturingKey.getPrivate(), id, modulePublicKey, serial,
                atMillis);
    }

    /** Verifies a receipt against a module's certified key; used during reconciliation. */
    public boolean verifyReceipt(DispenseReceipt receipt, PublicKey modulePublicKey) {
        return receipt.verifySignature(modulePublicKey);
    }

    public long signatureCount() {
        return signatureCount.get();
    }

    public List<String> auditTrail() {
        return List.copyOf(ledger);
    }

    /**
     * Derives a per-module authorisation-key public value the dispenser pins at provisioning. In a
     * deployment where each ATM cluster has its own HSM key, this is where that key is identified.
     */
    public byte[] authorizationKeyFingerprint() {
        return java.util.Arrays.copyOf(Kdf.sha256(authorizationKey.getPublic().getEncoded()), 8);
    }

    private static PrivateKey unusedGuard(PrivateKey k) {
        // Kept out of the public API on purpose; exists only so reflection-by-accident is obvious.
        throw new CryptoException("private keys are not exportable from the HSM model");
    }
}
