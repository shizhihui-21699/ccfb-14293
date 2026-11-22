package com.bank.atmsecure.auth;

import com.bank.atmsecure.crypto.Canonical;
import com.bank.atmsecure.crypto.CryptoException;
import com.bank.atmsecure.crypto.Ed25519;
import com.bank.atmsecure.model.CashPlan;
import com.bank.atmsecure.model.Money;
import com.bank.atmsecure.model.ModuleId;
import com.bank.atmsecure.model.Protocol;
import com.bank.atmsecure.model.TerminalId;
import com.bank.atmsecure.model.TxId;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * The dispenser's signed, non-repudiable statement that it actually moved a specific set of notes.
 *
 * <p>Signed by the module's own key (proven present in the handshake), chained to the previous
 * receipt via {@code prevReceiptHash} and carrying a strictly increasing {@code moduleSeq}. That
 * chain is what makes offline reconciliation possible: the host can prove a module did not skip,
 * reorder or drop a receipt, and can match every offline spend to a burned envelope budget.
 *
 * <p>It records the cash actually dispensed, so it is the settlement artefact — not a status a
 * terminal could fabricate.
 */
public final class DispenseReceipt {
    public static final String DOMAIN = "dispense-receipt-v1";

    private final int version;
    private final ModuleId moduleId;
    private final TerminalId terminalId;
    private final TxId txId;
    private final boolean offline;
    private final String offlineEnvelopeId;
    private final long amountCents;
    private final CashPlan plan;
    private final long authorizedSeq;
    private final long moduleSeq;
    private final byte[] prevReceiptHash;
    private final long cardInsertedAtMillis;
    private final long completedAtMillis;
    private final byte[] authorizationDigest;
    private final byte[] signature;

    private DispenseReceipt(Builder b) {
        this.version = Protocol.VERSION;
        this.moduleId = b.moduleId;
        this.terminalId = b.terminalId;
        this.txId = b.txId;
        this.offline = b.offline;
        this.offlineEnvelopeId = b.offlineEnvelopeId;
        this.amountCents = b.amountCents;
        this.plan = b.plan;
        this.authorizedSeq = b.authorizedSeq;
        this.moduleSeq = b.moduleSeq;
        this.prevReceiptHash = Canonical.copy(b.prevReceiptHash);
        this.cardInsertedAtMillis = b.cardInsertedAtMillis;
        this.completedAtMillis = b.completedAtMillis;
        this.authorizationDigest = Canonical.copy(b.authorizationDigest);
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

    public boolean offline() {
        return offline;
    }

    public String offlineEnvelopeId() {
        return offlineEnvelopeId;
    }

    public long amountCents() {
        return amountCents;
    }

    public CashPlan plan() {
        return plan;
    }

    public long authorizedSeq() {
        return authorizedSeq;
    }

    public long moduleSeq() {
        return moduleSeq;
    }

    public byte[] prevReceiptHash() {
        return Canonical.copy(prevReceiptHash);
    }

    public long completedAtMillis() {
        return completedAtMillis;
    }

    public long cardInsertedAtMillis() {
        return cardInsertedAtMillis;
    }

    public byte[] authorizationDigest() {
        return Canonical.copy(authorizationDigest);
    }

    public byte[] signature() {
        return Canonical.copy(signature);
    }

    public byte[] unsignedBytes() {
        Canonical.Writer w = Canonical.domain(DOMAIN);
        w.u16(version);
        w.str(moduleId.value());
        w.str(terminalId.value());
        w.str(txId.value());
        w.bool(offline);
        w.str(offlineEnvelopeId == null ? "" : offlineEnvelopeId);
        w.u64(amountCents);
        plan.encode(w);
        w.u64(authorizedSeq);
        w.u64(moduleSeq);
        w.bytes(prevReceiptHash);
        w.u64(cardInsertedAtMillis);
        w.u64(completedAtMillis);
        w.bytes(authorizationDigest);
        return w.toByteArray();
    }

    public DispenseReceipt signedBy(PrivateKey moduleKey) {
        Builder b = toBuilder();
        b.signature = Ed25519.sign(moduleKey, unsignedBytes());
        return new DispenseReceipt(b);
    }

    public boolean verifySignature(PublicKey modulePublicKey) {
        return Ed25519.verify(modulePublicKey, unsignedBytes(), signature);
    }

    public byte[] hash() {
        return com.bank.atmsecure.crypto.Kdf.sha256(unsignedBytes(), signature);
    }

    public byte[] encode() {
        Canonical.Writer w = new Canonical.Writer();
        w.bytes(unsignedBytes());
        w.bytes(signature);
        return w.toByteArray();
    }

    public static DispenseReceipt decode(byte[] encoded) {
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
            throw new CryptoException("wrong receipt domain");
        }
        Builder b = new Builder();
        b.version = br.u16();
        if (b.version != Protocol.VERSION) {
            throw new CryptoException("receipt version unsupported");
        }
        b.moduleId = new ModuleId(br.str());
        b.terminalId = new TerminalId(br.str());
        b.txId = new TxId(br.str());
        b.offline = br.bool();
        String env = br.str();
        b.offlineEnvelopeId = env.isEmpty() ? null : env;
        b.amountCents = br.u64();
        b.plan = CashPlan.decode(br);
        b.authorizedSeq = br.u64();
        b.moduleSeq = br.u64();
        b.prevReceiptHash = br.bytes();
        b.cardInsertedAtMillis = br.u64();
        b.completedAtMillis = br.u64();
        b.authorizationDigest = br.bytes();
        b.signature = sig;
        br.expectEnd();
        if (b.amountCents < 0 || b.amountCents > Money.MAX_CENTS
                || b.amountCents != b.plan.totalCents()) {
            throw new CryptoException("receipt amount/plan mismatch");
        }
        if (b.prevReceiptHash.length != Protocol.HASH_BYTES) {
            throw new CryptoException("receipt chain hash wrong length");
        }
        if (b.offline != (b.offlineEnvelopeId != null)) {
            throw new CryptoException("receipt offline/envelope inconsistency");
        }
        return new DispenseReceipt(b);
    }

    private Builder toBuilder() {
        Builder b = new Builder();
        b.moduleId = moduleId;
        b.terminalId = terminalId;
        b.txId = txId;
        b.offline = offline;
        b.offlineEnvelopeId = offlineEnvelopeId;
        b.amountCents = amountCents;
        b.plan = plan;
        b.authorizedSeq = authorizedSeq;
        b.moduleSeq = moduleSeq;
        b.prevReceiptHash = prevReceiptHash;
        b.cardInsertedAtMillis = cardInsertedAtMillis;
        b.completedAtMillis = completedAtMillis;
        b.authorizationDigest = authorizationDigest;
        b.signature = signature;
        return b;
    }

    @Override
    public String toString() {
        return "Receipt[" + txId + " " + Money.ofCents(amountCents) + " " + plan + " seq="
                + moduleSeq + (offline ? " OFFLINE/" + offlineEnvelopeId : " online") + "]";
    }

    public static final class Builder {
        private int version = Protocol.VERSION;
        private ModuleId moduleId;
        private TerminalId terminalId;
        private TxId txId;
        private boolean offline;
        private String offlineEnvelopeId;
        private long amountCents;
        private CashPlan plan;
        private long authorizedSeq;
        private long moduleSeq;
        private byte[] prevReceiptHash = new byte[Protocol.HASH_BYTES];
        private long cardInsertedAtMillis;
        private long completedAtMillis;
        private byte[] authorizationDigest = new byte[Protocol.HASH_BYTES];
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

        public Builder offline(boolean v) {
            this.offline = v;
            return this;
        }

        public Builder offlineEnvelopeId(String v) {
            this.offlineEnvelopeId = v;
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

        public Builder authorizedSeq(long v) {
            this.authorizedSeq = v;
            return this;
        }

        public Builder moduleSeq(long v) {
            this.moduleSeq = v;
            return this;
        }

        public Builder prevReceiptHash(byte[] v) {
            this.prevReceiptHash = v;
            return this;
        }

        public Builder cardInsertedAtMillis(long v) {
            this.cardInsertedAtMillis = v;
            return this;
        }

        public Builder completedAtMillis(long v) {
            this.completedAtMillis = v;
            return this;
        }

        public Builder authorizationDigest(byte[] v) {
            this.authorizationDigest = v;
            return this;
        }

        public DispenseReceipt build() {
            if (moduleId == null || terminalId == null || txId == null || plan == null) {
                throw new IllegalStateException("incomplete receipt");
            }
            if (amountCents != plan.totalCents()) {
                throw new IllegalArgumentException("receipt amount != plan total");
            }
            return new DispenseReceipt(this);
        }
    }
}
