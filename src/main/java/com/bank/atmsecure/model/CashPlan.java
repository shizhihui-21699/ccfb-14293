package com.bank.atmsecure.model;

import com.bank.atmsecure.crypto.Canonical;
import java.util.Collections;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

/**
 * Exact multiset of notes to be moved out of the cassettes.
 *
 * <p>The plan, not just the amount, is part of the host-signed authorisation. If only the total were
 * signed, a compromised terminal could ask for a hundred 100-yuan notes when the host authorised two
 * hundred 50-yuan notes and still satisfy "amount = 10 000". Binding the plan also makes the physical
 * result auditable against the signature.
 *
 * <p>Canonical form: denominations strictly ascending, each count in 1..{@link #MAX_PER_DENOMINATION},
 * total notes at most {@link #MAX_NOTES}.
 */
public final class CashPlan {
    public static final int MAX_PER_DENOMINATION = 200;
    public static final int MAX_NOTES = 400;

    private final SortedMap<Integer, Integer> countsByCents;

    private CashPlan(SortedMap<Integer, Integer> counts) {
        this.countsByCents = Collections.unmodifiableSortedMap(counts);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static CashPlan single(Denomination d, int count) {
        return builder().add(d, count).build();
    }

    /** Parses "100x20,50x0" style diagnostics into a plan; mainly for tests and the demo. */
    public static CashPlan parse(String spec) {
        Builder b = builder();
        if (spec == null || spec.isBlank()) {
            return b.build();
        }
        for (String part : spec.split(",")) {
            String[] p = part.trim().split("x");
            if (p.length != 2) {
                throw new IllegalArgumentException("bad plan component: " + part);
            }
            b.add(Denomination.fromCents(Integer.parseInt(p[0].trim()) * 100),
                    Integer.parseInt(p[1].trim()));
        }
        return b.build();
    }

    public long totalCents() {
        long total = 0;
        for (Map.Entry<Integer, Integer> e : countsByCents.entrySet()) {
            total = Math.addExact(total, (long) e.getKey() * e.getValue());
        }
        return total;
    }

    public int totalNotes() {
        int n = 0;
        for (int c : countsByCents.values()) {
            n += c;
        }
        return n;
    }

    public Map<Denomination, Integer> notes() {
        Map<Denomination, Integer> out = new TreeMap<>();
        for (Map.Entry<Integer, Integer> e : countsByCents.entrySet()) {
            out.put(Denomination.fromCents(e.getKey()), e.getValue());
        }
        return Collections.unmodifiableMap(out);
    }

    public int countOf(Denomination d) {
        return countsByCents.getOrDefault(d.cents(), 0);
    }

    public void encode(Canonical.Writer w) {
        w.u8(countsByCents.size());
        for (Map.Entry<Integer, Integer> e : countsByCents.entrySet()) {
            w.u16(e.getKey());
            w.u16(e.getValue());
        }
    }

    public static CashPlan decode(Canonical.Reader r) {
        int n = r.u8();
        if (n > Denomination.values().length) {
            throw new IllegalArgumentException("too many denomination entries: " + n);
        }
        Builder b = builder();
        int last = -1;
        for (int i = 0; i < n; i++) {
            int cents = r.u16();
            int count = r.u16();
            if (cents <= last) {
                throw new IllegalArgumentException("denominations not strictly ascending");
            }
            last = cents;
            b.add(Denomination.fromCents(cents), count);
        }
        return b.build();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<Integer, Integer> e : countsByCents.entrySet()) {
            if (sb.length() > 0) {
                sb.append(',');
            }
            sb.append(e.getKey() / 100).append('x').append(e.getValue());
        }
        return sb.length() == 0 ? "(empty)" : sb.toString();
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof CashPlan p && p.countsByCents.equals(countsByCents);
    }

    @Override
    public int hashCode() {
        return countsByCents.hashCode();
    }

    public static final class Builder {
        private final SortedMap<Integer, Integer> counts = new TreeMap<>();

        public Builder add(Denomination d, int count) {
            if (count < 0) {
                throw new IllegalArgumentException("negative count");
            }
            if (count == 0) {
                return this;
            }
            counts.merge(d.cents(), count, Math::addExact);
            return this;
        }

        public CashPlan build() {
            int totalNotes = 0;
            for (Map.Entry<Integer, Integer> e : counts.entrySet()) {
                Denomination.fromCents(e.getKey());
                if (e.getValue() > MAX_PER_DENOMINATION) {
                    throw new IllegalArgumentException("too many notes of one denomination: "
                            + e.getValue());
                }
                totalNotes += e.getValue();
            }
            if (totalNotes > MAX_NOTES) {
                throw new IllegalArgumentException("plan exceeds " + MAX_NOTES + " notes");
            }
            if (counts.isEmpty()) {
                throw new IllegalArgumentException("empty cash plan");
            }
            return new CashPlan(new TreeMap<>(counts));
        }
    }
}
