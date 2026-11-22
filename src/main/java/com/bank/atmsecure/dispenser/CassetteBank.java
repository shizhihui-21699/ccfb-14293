package com.bank.atmsecure.dispenser;

import com.bank.atmsecure.crypto.Canonical;
import com.bank.atmsecure.model.CashPlan;
import com.bank.atmsecure.model.Denomination;
import com.bank.atmsecure.model.Money;
import java.util.EnumMap;
import java.util.Map;

/**
 * The four cassettes. Deliberately simple: each holds one denomination with a physical count.
 *
 * <p>Dispensing is all-or-nothing. The module never partially fulfils a plan and then reports a
 * different amount, because the host authorisation binds an exact plan and the receipt must match it
 * note-for-note.
 */
public final class CassetteBank {
    public static final int CAPACITY_PER_CASSETTE = 2000;

    private final EnumMap<Denomination, Integer> counts = new EnumMap<>(Denomination.class);

    public CassetteBank() {
        for (Denomination d : Denomination.values()) {
            counts.put(d, 0);
        }
    }

    /** Factory/service load. Rejects over-capacity loads rather than silently truncating. */
    public synchronized void load(Denomination d, int count) {
        if (count < 0 || count > CAPACITY_PER_CASSETTE) {
            throw new IllegalArgumentException("bad cassette load " + count);
        }
        counts.put(d, count);
    }

    public synchronized int countOf(Denomination d) {
        return counts.get(d);
    }

    public synchronized Money totalValue() {
        long cents = 0;
        for (Map.Entry<Denomination, Integer> e : counts.entrySet()) {
            cents += (long) e.getKey().cents() * e.getValue();
        }
        return Money.ofCents(cents);
    }

    public synchronized boolean canFulfil(CashPlan plan) {
        for (Map.Entry<Denomination, Integer> e : plan.notes().entrySet()) {
            if (counts.get(e.getKey()) < e.getValue()) {
                return false;
            }
        }
        return true;
    }

    /** Removes the plan. Caller must have checked {@link #canFulfil(CashPlan)} under the same lock. */
    synchronized void remove(CashPlan plan) {
        for (Map.Entry<Denomination, Integer> e : plan.notes().entrySet()) {
            int left = counts.get(e.getKey()) - e.getValue();
            if (left < 0) {
                throw new IllegalStateException("cassette underflow on " + e.getKey());
            }
            counts.put(e.getKey(), left);
        }
    }

    public synchronized Map<Denomination, Integer> snapshot() {
        return new EnumMap<>(counts);
    }

    public synchronized byte[] encodeState() {
        Canonical.Writer w = new Canonical.Writer();
        w.u8(Denomination.values().length);
        for (Denomination d : Denomination.values()) {
            w.u16(d.cents());
            w.u16(counts.get(d));
        }
        return w.toByteArray();
    }

    public static CassetteBank decodeState(byte[] raw) {
        Canonical.Reader r = new Canonical.Reader(raw);
        int n = r.u8();
        CassetteBank b = new CassetteBank();
        for (int i = 0; i < n; i++) {
            Denomination d = Denomination.fromCents(r.u16());
            b.load(d, r.u16());
        }
        r.expectEnd();
        return b;
    }

    public synchronized String describe() {
        StringBuilder sb = new StringBuilder();
        for (Denomination d : Denomination.values()) {
            if (sb.length() > 0) {
                sb.append(" ");
            }
            sb.append(d.cents() / 100).append("yuan=").append(counts.get(d));
        }
        return sb.toString();
    }
}
