package com.bank.atmsecure.model;

/**
 * Amount of money in minor units (fen / cents). Deliberately not {@code double}: money must never
 * round. The whole protocol carries {@code long} cents.
 */
public final class Money {
    /** Upper bound for a single dispense: 200 000.00 CNY. Well above ATM per-transaction limits. */
    public static final long MAX_CENTS = 20_000_000L;

    private final long cents;

    private Money(long cents) {
        this.cents = cents;
    }

    public static Money ofCents(long cents) {
        if (cents < 0 || cents > MAX_CENTS) {
            throw new IllegalArgumentException("amount out of range: " + cents);
        }
        return new Money(cents);
    }

    public static Money ofYuan(long yuan) {
        return ofCents(Math.multiplyExact(yuan, 100L));
    }

    public long cents() {
        return cents;
    }

    public Money plus(Money other) {
        return ofCents(Math.addExact(cents, other.cents));
    }

    public Money minus(Money other) {
        if (other.cents > cents) {
            throw new IllegalArgumentException("negative result");
        }
        return new Money(cents - other.cents);
    }

    public boolean isZero() {
        return cents == 0;
    }

    public boolean atMost(Money other) {
        return cents <= other.cents;
    }

    public Money multiply(int n) {
        return ofCents(Math.multiplyExact(cents, (long) n));
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Money m && m.cents == cents;
    }

    @Override
    public int hashCode() {
        return Long.hashCode(cents);
    }

    @Override
    public String toString() {
        return String.format("%d.%02d", cents / 100, cents % 100);
    }
}
