package com.bank.atmsecure.auth;

import com.bank.atmsecure.crypto.Canonical;
import com.bank.atmsecure.crypto.CryptoException;
import com.bank.atmsecure.crypto.Ed25519;
import com.bank.atmsecure.model.CashPlan;
import com.bank.atmsecure.model.ModuleId;
import com.bank.atmsecure.model.Money;
import com.bank.atmsecure.model.Protocol;
import com.bank.atmsecure.model.TerminalId;
import com.bank.atmsecure.model.TxId;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * The single most important message in the system: the host's signed permission to move one exact
 * set of notes out of one exact dispenser, once.
 *
 * <p>Security properties, each of which has a dedicated attack test:
 * <ul>
 *   <li><b>Host authority.</b> Only the host HSM holds the signing key. The dispenser pins its public
 *       half at manufacture. Replacing the terminal PC therefore yields no signing ability.</li>
 *   <li><b>Module binding.</b> {@code moduleId} is inside the signature, so an authorisation for
 *       ATM-1's dispenser cannot be replayed to ATM-2's.</li>
 *   <li><b>Terminal binding.</b> An authorisation minted for terminal T is rejected by a module paired
 *       to a different terminal.</li>
 *   <li><b>Exact plan binding.</b> {@code amountCents} must equal the signed plan's total; the module
 *       rejects any mismatch. The plan is itself signed, so the physical notes match the receipt.</li>
 *   <li><b>Freshness.</b> The dispenser's own one-time {@code nonce} and the link's
 *       {@code channelBinding} are signed, so a captured authorisation is useless in another session
 *       or after the nonce is consumed.</li>
 *   <li><b>Ordering.</b> Host-assigned {@code seq} must strictly increase per module.</li>
 *   <li><b>Epoch.</b> {@code keyEpoch} must equal the module's current pairing epoch; re-pairing a
 *       module invalidates every authorisation minted under the old epoch.</li>
 * </ul>
 */
public final class HostAuthorization {
    public static final String DOMAIN = "host-dispense-authorization-v1";

    private final int version;
    private final ModuleId moduleId;
    private final TerminalId terminalId;
    private final TxId txId;
    private final long amountCents;
    private final CashPlan plan;
    private final byte[] nonce;
    private final byte[] channelBinding;
    private final long seq;
    private final long issuedAtMillis;
    private final long expiresAtMillis;
    private final int keyEpoch;
    private final byte[] signature;

    private HostAuthorization(Builder b) {
        this.version = Protocol.VERSION;
        this.moduleId = b.moduleId;
        this.terminalId = b.terminalId;
        this.txId = b.txId;
        this.amountCents = b.amountCents;
        this.plan = b.plan;
        this.nonce = Canonical.copy(b.nonce);
        this.channelBinding = Canonical.copy(b.channelBinding);
        this.seq = b.seq;
        this.issuedAtMillis = b.issuedAtMillis;
        this.expiresAtMillis = b.expiresAtMillis;
        this.keyEpoch = b.keyEpoch;
        this.signature = Canonical.copy(b.signature);
    }

    public static Builder builder() {
        return new Builder();
    }

    public int version() {
        return version;
    }

    public ModuleId moduleId() {
        return moduleId;
    }

    public TerminalId terminalId() {
        return terminalId;
    }

    public TxId txId() {
        return txId;
    }

    public long amountCents() {
        return amountCents;
    }

    public CashPlan plan() {
        return plan;
    }

    public byte[] nonce() {
        return Canonical.copy(nonce);
    }

    public byte[] channelBinding() {
        return Canonical.copy(channelBinding);
    }

    public long seq() {
        return seq;
    }

    public long issuedAtMillis() {
        return issuedAtMillis;
    }

    public long expiresAtMillis() {
        return expiresAtMillis;
    }

    public int keyEpoch() {
        return keyEpoch;
    }

    public byte[] signature() {
        return Canonical.copy(signature);
    }

    /** The exact bytes the host signs and the module verifies. Signature excluded. */
    public byte[] unsignedBytes() {
        Canonical.Writer w = Canonical.domain(DOMAIN);
        w.u16(version);
        w.str(moduleId.value());
        w.str(terminalId.value());
        w.str(txId.value());
        w.u64(amountCents);
        plan.encode(w);
        w.bytes(nonce);
        w.bytes(channelBinding);
        w.u64(seq);
        w.u64(issuedAtMillis);
        w.u64(expiresAtMillis);
        w.u32(keyEpoch);
        return w.toByteArray();
    }

    public HostAuthorization signedBy(PrivateKey hostKey) {
        Builder copy = toBuilder();
        copy.signature = Ed25519.sign(hostKey, unsignedBytes());
        return new HostAuthorization(copy);
    }

    public boolean verifySignature(PublicKey hostPublicKey) {
        return Ed25519.verify(hostPublicKey, unsignedBytes(), signature);
    }

    public byte[] digest() {
        return com.bank.atmsecure.crypto.Kdf.sha256(unsignedBytes());
    }

    public byte[] encode() {
        Canonical.Writer w = new Canonical.Writer();
        w.bytes(unsignedBytes());
        w.bytes(signature);
        return w.toByteArray();
    }

    public static HostAuthorization decode(byte[] encoded) {
        Canonical.Reader r = new Canonical.Reader(encoded);
        byte[] body = r.bytes();
        byte[] sig = r.bytes();
        r.expectEnd();
        return parse(body, sig);
    }

    private static HostAuthorization parse(byte[] body, byte[] sig) {
        Canonical.Reader r = new Canonical.Reader(body);
        byte[] magic = r.fixed(4);
        if (magic[0] != 'A' || magic[1] != 'T' || magic[2] != 'M' || magic[3] != '1') {
            throw new CryptoException("bad domain magic");
        }
        if (!DOMAIN.equals(r.str())) {
            throw new CryptoException("wrong authorization domain");
        }
        int version = r.u16();
        if (version != Protocol.VERSION) {
            throw new CryptoException("authorization protocol version " + version + " unsupported");
        }
        Builder b = builder();
        b.moduleId = new ModuleId(r.str());
        b.terminalId = new TerminalId(r.str());
        b.txId = new TxId(r.str());
        b.amountCents = r.u64();
        b.plan = CashPlan.decode(r);
        b.nonce = r.bytes();
        b.channelBinding = r.bytes();
        b.seq = r.u64();
        b.issuedAtMillis = r.u64();
        b.expiresAtMillis = r.u64();
        b.keyEpoch = (int) r.u32();
        b.signature = sig;
        r.expectEnd();
        if (b.amountCents < 0 || b.amountCents > Money.MAX_CENTS) {
            throw new CryptoException("authorization amount out of range");
        }
        if (b.nonce.length != Protocol.NONCE_BYTES) {
            throw new CryptoException("authorization nonce wrong length");
        }
        if (b.channelBinding.length != Protocol.CHANNEL_BINDING_BYTES) {
            throw new CryptoException("authorization channel binding wrong length");
        }
        return new HostAuthorization(b);
    }

    private Builder toBuilder() {
        Builder b = new Builder();
        b.moduleId = moduleId;
        b.terminalId = terminalId;
        b.txId = txId;
        b.amountCents = amountCents;
        b.plan = plan;
        b.nonce = nonce;
        b.channelBinding = channelBinding;
        b.seq = seq;
        b.issuedAtMillis = issuedAtMillis;
        b.expiresAtMillis = expiresAtMillis;
        b.keyEpoch = keyEpoch;
        b.signature = signature;
        return b;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof HostAuthorization a)) {
            return false;
        }
        return version == a.version && amountCents == a.amountCents && seq == a.seq
                && issuedAtMillis == a.issuedAtMillis && expiresAtMillis == a.expiresAtMillis
                && keyEpoch == a.keyEpoch && moduleId.equals(a.moduleId)
                && terminalId.equals(a.terminalId) && txId.equals(a.txId)
                && plan.equals(a.plan) && Arrays.equals(nonce, a.nonce)
                && Arrays.equals(channelBinding, a.channelBinding)
                && Arrays.equals(signature, a.signature);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(moduleId, terminalId, txId, amountCents, plan, seq);
    }

    @Override
    public String toString() {
        return "HostAuthorization[" + txId + " " + moduleId + "/" + terminalId + " "
                + Money.ofCents(amountCents) + " " + plan + " seq=" + seq + " epoch=" + keyEpoch + "]";
    }

    public static final class Builder {
        private ModuleId moduleId;
        private TerminalId terminalId;
        private TxId txId;
        private long amountCents;
        private CashPlan plan;
        private byte[] nonce;
        private byte[] channelBinding;
        private long seq;
        private long issuedAtMillis;
        private long expiresAtMillis;
        private int keyEpoch;
        private byte[] signature;

        public Builder moduleId(ModuleId v) {
            this.moduleId = v;
            return this;
        }

        public Builder terminalId(TerminalId v) {
            this.terminalId = v;
            return this;
        }

        public Builder txId(TxId v) {
            this.txId = v;
            return this;
        }

        public Builder amount(Money v) {
            this.amountCents = v.cents();
            return this;
        }

        public Builder amountCents(long v) {
            this.amountCents = v;
            return this;
        }

        public Builder plan(CashPlan v) {
            this.plan = v;
            return this;
        }

        public Builder nonce(byte[] v) {
            this.nonce = v;
            return this;
        }

        public Builder channelBinding(byte[] v) {
            this.channelBinding = v;
            return this;
        }

        public Builder seq(long v) {
            this.seq = v;
            return this;
        }

        public Builder validity(long issuedAtMillis, long expiresAtMillis) {
            this.issuedAtMillis = issuedAtMillis;
            this.expiresAtMillis = expiresAtMillis;
            return this;
        }

        public Builder keyEpoch(int v) {
            this.keyEpoch = v;
            return this;
        }

        public HostAuthorization build() {
            if (moduleId == null || terminalId == null || txId == null || plan == null
                    || nonce == null || channelBinding == null) {
                throw new IllegalStateException("incomplete authorization");
            }
            if (amountCents != plan.totalCents()) {
                throw new IllegalArgumentException("amount " + amountCents
                        + " does not match plan total " + plan.totalCents());
            }
            if (expiresAtMillis <= issuedAtMillis) {
                throw new IllegalArgumentException("expiry must follow issue time");
            }
            return new HostAuthorization(this);
        }
    }
}
