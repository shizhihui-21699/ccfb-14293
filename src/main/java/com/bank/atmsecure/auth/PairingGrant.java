package com.bank.atmsecure.auth;

import com.bank.atmsecure.crypto.Canonical;
import com.bank.atmsecure.crypto.CryptoException;
import com.bank.atmsecure.crypto.Ed25519;
import com.bank.atmsecure.model.ModuleId;
import com.bank.atmsecure.model.TerminalId;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Signed work order permitting a service technician to bind one module to one terminal at a new
 * pairing epoch.
 *
 * <p>Re-pairing is the operation most abused in real ATM fraud, so it needs three independent gates:
 * <ol>
 *   <li><b>Host signature.</b> Only the bank's service-authority key can mint a grant; the module has
 *       its public half pinned in OTP flash alongside the manufacturing key.</li>
 *   <li><b>Physical presence.</b> The module's service jumper/keyswitch must be closed. This is the
 *       hardware interlock a remote attacker cannot flip.</li>
 *   <li><b>Single use + short validity.</b> The grant id is burned into flash on acceptance, and the
 *       grant names the exact module, terminal, technician and work order, so a leaked grant cannot
 *       be repurposed.</li>
 * </ol>
 */
public final class PairingGrant {
    public static final String DOMAIN = "module-pairing-grant-v1";

    /**
     * A signed grant together with the callback that updates host state <em>after</em> the module
     * accepts it. This keeps the ledger from being advanced by a grant that never took effect.
     */
    public record IssuedPairing(PairingGrant grant, java.util.function.Consumer<Boolean> commit) {
    }

    private final String grantId;
    private final ModuleId moduleId;
    private final TerminalId terminalId;
    private final String technicianId;
    private final String workOrderId;
    private final int newKeyEpoch;
    private final long issuedAtMillis;
    private final long expiresAtMillis;
    private final byte[] signature;

    private PairingGrant(Builder b) {
        this.grantId = b.grantId;
        this.moduleId = b.moduleId;
        this.terminalId = b.terminalId;
        this.technicianId = b.technicianId;
        this.workOrderId = b.workOrderId;
        this.newKeyEpoch = b.newKeyEpoch;
        this.issuedAtMillis = b.issuedAtMillis;
        this.expiresAtMillis = b.expiresAtMillis;
        this.signature = Canonical.copy(b.signature);
    }

    public static Builder builder() {
        return new Builder();
    }

    public String grantId() {
        return grantId;
    }

    public ModuleId moduleId() {
        return moduleId;
    }

    public TerminalId terminalId() {
        return terminalId;
    }

    public String technicianId() {
        return technicianId;
    }

    public String workOrderId() {
        return workOrderId;
    }

    public int newKeyEpoch() {
        return newKeyEpoch;
    }

    public long issuedAtMillis() {
        return issuedAtMillis;
    }

    public long expiresAtMillis() {
        return expiresAtMillis;
    }

    public byte[] unsignedBytes() {
        Canonical.Writer w = Canonical.domain(DOMAIN);
        w.str(grantId);
        w.str(moduleId.value());
        w.str(terminalId.value());
        w.str(technicianId);
        w.str(workOrderId);
        w.u32(newKeyEpoch);
        w.u64(issuedAtMillis);
        w.u64(expiresAtMillis);
        return w.toByteArray();
    }

    public PairingGrant signedBy(PrivateKey serviceKey) {
        Builder b = new Builder();
        b.grantId = grantId;
        b.moduleId = moduleId;
        b.terminalId = terminalId;
        b.technicianId = technicianId;
        b.workOrderId = workOrderId;
        b.newKeyEpoch = newKeyEpoch;
        b.issuedAtMillis = issuedAtMillis;
        b.expiresAtMillis = expiresAtMillis;
        b.signature = Ed25519.sign(serviceKey, unsignedBytes());
        return new PairingGrant(b);
    }

    public boolean verifySignature(PublicKey serviceKey) {
        return Ed25519.verify(serviceKey, unsignedBytes(), signature);
    }

    public byte[] encode() {
        Canonical.Writer w = new Canonical.Writer();
        w.bytes(unsignedBytes());
        w.bytes(signature);
        return w.toByteArray();
    }

    public static PairingGrant decode(byte[] encoded) {
        Canonical.Reader r = new Canonical.Reader(encoded);
        byte[] body = r.bytes();
        byte[] sig = r.bytes();
        r.expectEnd();
        Canonical.Reader br = new Canonical.Reader(body);
        byte[] magic = br.fixed(4);
        if (magic[0] != 'A' || magic[1] != 'T' || magic[2] != 'M' || magic[3] != '1') {
            throw new CryptoException("bad domain magic");
        }
        if (!DOMAIN.equals(br.str())) {
            throw new CryptoException("wrong grant domain");
        }
        Builder b = new Builder();
        b.grantId = br.str();
        b.moduleId = new ModuleId(br.str());
        b.terminalId = new TerminalId(br.str());
        b.technicianId = br.str();
        b.workOrderId = br.str();
        b.newKeyEpoch = (int) br.u32();
        b.issuedAtMillis = br.u64();
        b.expiresAtMillis = br.u64();
        b.signature = sig;
        br.expectEnd();
        return new PairingGrant(b);
    }

    @Override
    public String toString() {
        return "PairingGrant[" + grantId + " " + moduleId + "->" + terminalId
                + " epoch=" + newKeyEpoch + " workOrder=" + workOrderId + "]";
    }

    public static final class Builder {
        private String grantId;
        private ModuleId moduleId;
        private TerminalId terminalId;
        private String technicianId;
        private String workOrderId;
        private int newKeyEpoch;
        private long issuedAtMillis;
        private long expiresAtMillis;
        private byte[] signature;

        public Builder grantId(String v) {
            this.grantId = v;
            return this;
        }

        public Builder moduleId(ModuleId v) {
            this.moduleId = v;
            return this;
        }

        public Builder terminalId(TerminalId v) {
            this.terminalId = v;
            return this;
        }

        public Builder technicianId(String v) {
            this.technicianId = v;
            return this;
        }

        public Builder workOrderId(String v) {
            this.workOrderId = v;
            return this;
        }

        public Builder newKeyEpoch(int v) {
            this.newKeyEpoch = v;
            return this;
        }

        public Builder validity(long issuedAtMillis, long expiresAtMillis) {
            this.issuedAtMillis = issuedAtMillis;
            this.expiresAtMillis = expiresAtMillis;
            return this;
        }

        public PairingGrant build() {
            if (grantId == null || moduleId == null || terminalId == null || technicianId == null
                    || workOrderId == null || expiresAtMillis <= issuedAtMillis) {
                throw new IllegalStateException("incomplete pairing grant");
            }
            return new PairingGrant(this);
        }
    }
}
