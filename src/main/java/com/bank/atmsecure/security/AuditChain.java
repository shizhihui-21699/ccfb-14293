package com.bank.atmsecure.security;

import com.bank.atmsecure.crypto.Canonical;
import com.bank.atmsecure.crypto.Hex;
import com.bank.atmsecure.crypto.Kdf;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

/**
 * Tamper-evident audit log inside the dispenser.
 *
 * <p>Append-only and hash-chained: each entry commits to the previous entry's hash, so deleting or
 * editing a past entry breaks every later hash. The tip is mirrored into NVRAM and reported to the
 * host at reconciliation; a chip-off attacker who restores an old log is caught when the host compares
 * the expected chain against the receipts it settled.
 *
 * <p>The log is where the <em>precise</em> refusal reason lives. The wire answer is deliberately
 * coarse (see {@code DispenseStatus}) so the bus gives an attacker no oracle.
 */
public final class AuditChain {
    public enum Kind {
        SESSION_OPENED,
        NONCE_ISSUED,
        DISPENSE_OK,
        DISPENSE_REFUSED,
        AUTH_REJECTED,
        SEQ_REJECTED,
        NONCE_REJECTED,
        ENVELOPE_LOADED,
        ENVELOPE_REFUSED,
        TAMPER,
        ROLLBACK_DETECTED,
        PAIRING,
        HEALTH_FAILURE,
        THROTTLED
    }

    public record Entry(long index, long atMillis, Kind kind, String detail, byte[] prevHash,
            byte[] hash) {
        public String describe() {
            return "#" + index + " " + kind + (detail.isEmpty() ? "" : " " + detail);
        }
    }

    private final int capacity;
    private final Deque<Entry> entries = new ArrayDeque<>();
    private long nextIndex;
    private byte[] tip = new byte[32];

    public AuditChain(int capacity) {
        this.capacity = capacity;
    }

    /**
     * Seeds the running tip and index at boot so the chain is continuous across power cycles rather
     * than restarting from zero. The tip is mirrored in NVRAM; if that mirror was rolled back, the
     * chain continues from the older tip and the discrepancy surfaces against the OTP-anchored
     * receipt sequence at reconciliation.
     */
    public synchronized void restore(byte[] persistedTip, long persistedIndex) {
        if (persistedTip != null && persistedTip.length == 32) {
            tip = persistedTip.clone();
        }
        if (persistedIndex > 0) {
            nextIndex = persistedIndex;
        }
    }

    public synchronized long nextIndex() {
        return nextIndex;
    }

    public synchronized Entry append(long atMillis, Kind kind, String detail) {
        byte[] body = Canonical.domain("audit-entry-v1")
                .u64(nextIndex)
                .u64(atMillis)
                .str(kind.name())
                .str(detail == null ? "" : detail)
                .toByteArray();
        byte[] hash = Kdf.sha256(body, tip);
        Entry e = new Entry(nextIndex, atMillis, kind, detail == null ? "" : detail, tip.clone(),
                hash);
        nextIndex++;
        tip = hash;
        entries.addLast(e);
        while (entries.size() > capacity) {
            entries.removeFirst();
        }
        return e;
    }

    public synchronized byte[] tip() {
        return tip.clone();
    }

    public synchronized long count() {
        return nextIndex;
    }

    public synchronized List<Entry> recent() {
        return new ArrayList<>(entries);
    }

    public synchronized boolean verifyChain(List<Entry> chain) {
        byte[] prev = chain.isEmpty() ? new byte[32] : chain.get(0).prevHash();
        for (Entry e : chain) {
            byte[] body = Canonical.domain("audit-entry-v1")
                    .u64(e.index())
                    .u64(e.atMillis())
                    .str(e.kind().name())
                    .str(e.detail())
                    .toByteArray();
            if (!java.util.Arrays.equals(Kdf.sha256(body, prev), e.hash())) {
                return false;
            }
            prev = e.hash();
        }
        return true;
    }

    public synchronized String describeTip() {
        return "auditTip=" + Hex.encode(tip, 6) + " entries=" + nextIndex;
    }
}
