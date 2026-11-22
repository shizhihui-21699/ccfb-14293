package com.bank.atmsecure.auth;

import com.bank.atmsecure.crypto.Canonical;
import com.bank.atmsecure.crypto.CryptoException;
import com.bank.atmsecure.crypto.Ed25519;
import com.bank.atmsecure.model.ModuleId;
import com.bank.atmsecure.model.Money;
import com.bank.atmsecure.model.Protocol;
import com.bank.atmsecure.model.TerminalId;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Offline authority: a host-signed envelope that lets a dispenser spend while the host is unreachable.
 *
 * <h2>Why absolute caps, not a budget counter</h2>
 * A naive envelope says "you may spend 3000 over 3 transactions". The module then keeps a remaining
 * budget — which an attacker with a chip programmer can restore to "full". The fix is to make the
 * host authorise an <em>absolute, lifetime</em> ceiling that the module can compare against a
 * monotonic quantity it cannot rewind:
 * <ul>
 *   <li>the module keeps a lifetime cumulative <em>offline spend</em> (cents) and <em>offline
 *       transaction count</em>, each anchored in OTP and only ever increasing;</li>
 *   <li>the envelope carries {@code spendCapCents} and {@code txCountCap}, absolute ceilings computed
 *       by the host from the last reconciled cumulative values plus the budget/count it is granting;</li>
 *   <li>a dispense is allowed only if {@code cumulative + amount <= cap} and {@code count + 1 <=
 *       countCap}.</li>
 * </ul>
 * Now restoring an old NVRAM image cannot refill anything: the OTP floor keeps the cumulative spend
 * where it was, and the signed cap is fixed. Even replaying an old envelope after such a rollback
 * yields no extra money, because the cumulative spend already sits against the same absolute cap.
 *
 * <p>The host must therefore know each module's cumulative offline spend at issue time — it does, from
 * the signed receipts it reconciles after every connectivity window. If that state is stale, the cap
 * is simply conservative (the module refuses sooner), never permissive.
 */
public final class OfflineEnvelope {
    public static final String DOMAIN = "offline-dispense-envelope-v2";

    private final String envelopeId;
    private final ModuleId moduleId;
    private final TerminalId terminalId;
    private final int keyEpoch;
    private final long perTxMaxCents;
    private final long spendCapCents;
    private final long txCountCap;
    private final long seqStart;
    private final long seqEnd;
    private final long grantedBudgetCents;
    private final int grantedTransactions;
    private final long issuedAtMillis;
    private final long expiresAtMillis;
    private final byte[] signature;

    private OfflineEnvelope(Builder b) {
        this.envelopeId = b.envelopeId;
        this.moduleId = b.moduleId;
        this.terminalId = b.terminalId;
        this.keyEpoch = b.keyEpoch;
        this.perTxMaxCents = b.perTxMaxCents;
        this.spendCapCents = b.spendCapCents;
        this.txCountCap = b.txCountCap;
        this.seqStart = b.seqStart;
        this.seqEnd = b.seqEnd;
        this.grantedBudgetCents = b.grantedBudgetCents;
        this.grantedTransactions = b.grantedTransactions;
        this.issuedAtMillis = b.issuedAtMillis;
        this.expiresAtMillis = b.expiresAtMillis;
        this.signature = Canonical.copy(b.signature);
    }

    public static Builder builder() {
        return new Builder();
    }

    public String envelopeId() {
        return envelopeId;
    }

    public ModuleId moduleId() {
        return moduleId;
    }

    public TerminalId terminalId() {
        return terminalId;
    }

    public int keyEpoch() {
        return keyEpoch;
    }

    public Money perTxMax() {
        return Money.ofCents(perTxMaxCents);
    }

    /** Absolute lifetime ceiling on cumulative offline spend, in cents. */
    public long spendCapCents() {
        return spendCapCents;
    }

    /** Absolute lifetime ceiling on cumulative offline transaction count. */
    public long txCountCap() {
        return txCountCap;
    }

    public long seqStart() {
        return seqStart;
    }

    public long seqEnd() {
        return seqEnd;
    }

    public Money grantedBudget() {
        return Money.ofCents(grantedBudgetCents);
    }

    public int grantedTransactions() {
        return grantedTransactions;
    }

    public long issuedAtMillis() {
        return issuedAtMillis;
    }

    public long expiresAtMillis() {
        return expiresAtMillis;
    }

    public byte[] signature() {
        return Canonical.copy(signature);
    }

    public boolean coversAmount(Money amount) {
        return amount.cents() <= perTxMaxCents;
    }

    public byte[] fingerprint() {
        return com.bank.atmsecure.crypto.Kdf.sha256(Canonical.domain("offline-envelope-fp-v2")
                .str(envelopeId).str(moduleId.value()).u32(keyEpoch).toByteArray());
    }

    public byte[] unsignedBytes() {
        Canonical.Writer w = Canonical.domain(DOMAIN);
        w.u16(Protocol.VERSION);
        w.str(envelopeId);
        w.str(moduleId.value());
        w.str(terminalId.value());
        w.u32(keyEpoch);
        w.u64(perTxMaxCents);
        w.u64(spendCapCents);
        w.u64(txCountCap);
        w.u64(seqStart);
        w.u64(seqEnd);
        w.u64(grantedBudgetCents);
        w.u32(grantedTransactions);
        w.u64(issuedAtMillis);
        w.u64(expiresAtMillis);
        return w.toByteArray();
    }

    public OfflineEnvelope signedBy(PrivateKey hostKey) {
        Builder b = toBuilder();
        b.signature = Ed25519.sign(hostKey, unsignedBytes());
        return new OfflineEnvelope(b);
    }

    public boolean verifySignature(PublicKey hostPublicKey) {
        return Ed25519.verify(hostPublicKey, unsignedBytes(), signature);
    }

    public byte[] encode() {
        Canonical.Writer w = new Canonical.Writer();
        w.bytes(unsignedBytes());
        w.bytes(signature);
        return w.toByteArray();
    }

    public static OfflineEnvelope decode(byte[] encoded) {
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
            throw new CryptoException("wrong envelope domain");
        }
        int ver = br.u16();
        if (ver != Protocol.VERSION) {
            throw new CryptoException("envelope version unsupported");
        }
        Builder b = new Builder();
        b.envelopeId = br.str();
        b.moduleId = new ModuleId(br.str());
        b.terminalId = new TerminalId(br.str());
        b.keyEpoch = (int) br.u32();
        b.perTxMaxCents = br.u64();
        b.spendCapCents = br.u64();
        b.txCountCap = br.u64();
        b.seqStart = br.u64();
        b.seqEnd = br.u64();
        b.grantedBudgetCents = br.u64();
        b.grantedTransactions = (int) br.u32();
        b.issuedAtMillis = br.u64();
        b.expiresAtMillis = br.u64();
        b.signature = sig;
        br.expectEnd();
        if (b.perTxMaxCents <= 0 || b.spendCapCents < 0 || b.txCountCap < 0
                || b.seqEnd < b.seqStart || b.expiresAtMillis <= b.issuedAtMillis
                || b.spendCapCents > Money.MAX_CENTS) {
            throw new CryptoException("envelope parameters out of range");
        }
        return new OfflineEnvelope(b);
    }

    private Builder toBuilder() {
        Builder b = new Builder();
        b.envelopeId = envelopeId;
        b.moduleId = moduleId;
        b.terminalId = terminalId;
        b.keyEpoch = keyEpoch;
        b.perTxMaxCents = perTxMaxCents;
        b.spendCapCents = spendCapCents;
        b.txCountCap = txCountCap;
        b.seqStart = seqStart;
        b.seqEnd = seqEnd;
        b.grantedBudgetCents = grantedBudgetCents;
        b.grantedTransactions = grantedTransactions;
        b.issuedAtMillis = issuedAtMillis;
        b.expiresAtMillis = expiresAtMillis;
        b.signature = signature;
        return b;
    }

    @Override
    public String toString() {
        return "OfflineEnvelope[" + envelopeId + " " + moduleId + " perTx<="
                + Money.ofCents(perTxMaxCents) + " spendCap=" + Money.ofCents(spendCapCents)
                + " countCap=" + txCountCap + " seq=" + seqStart + ".." + seqEnd + "]";
    }

    public static final class Builder {
        private String envelopeId;
        private ModuleId moduleId;
        private TerminalId terminalId;
        private int keyEpoch;
        private long perTxMaxCents;
        private long spendCapCents;
        private long txCountCap;
        private long seqStart;
        private long seqEnd;
        private long grantedBudgetCents;
        private int grantedTransactions;
        private long issuedAtMillis;
        private long expiresAtMillis;
        private byte[] signature;

        public Builder envelopeId(String v) {
            this.envelopeId = v;
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

        public Builder keyEpoch(int v) {
            this.keyEpoch = v;
            return this;
        }

        public Builder perTxMax(Money v) {
            this.perTxMaxCents = v.cents();
            return this;
        }

        public Builder perTxMaxCents(long v) {
            this.perTxMaxCents = v;
            return this;
        }

        public Builder spendCapCents(long v) {
            this.spendCapCents = v;
            return this;
        }

        public Builder txCountCap(long v) {
            this.txCountCap = v;
            return this;
        }

        public Builder seqWindow(long start, long end) {
            this.seqStart = start;
            this.seqEnd = end;
            return this;
        }

        public Builder grantedBudget(Money v) {
            this.grantedBudgetCents = v.cents();
            return this;
        }

        public Builder grantedTransactions(int v) {
            this.grantedTransactions = v;
            return this;
        }

        public Builder validity(long issuedAtMillis, long expiresAtMillis) {
            this.issuedAtMillis = issuedAtMillis;
            this.expiresAtMillis = expiresAtMillis;
            return this;
        }

        public OfflineEnvelope build() {
            if (envelopeId == null || moduleId == null || terminalId == null
                    || perTxMaxCents <= 0 || spendCapCents < 0 || txCountCap < 0
                    || seqEnd < seqStart || expiresAtMillis <= issuedAtMillis) {
                throw new IllegalStateException("incomplete or invalid envelope");
            }
            return new OfflineEnvelope(this);
        }
    }
}
