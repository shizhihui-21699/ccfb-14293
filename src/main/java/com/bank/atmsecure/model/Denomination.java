package com.bank.atmsecure.model;

/** Notes an ATM cassette can hold. Values are in fen so they line up with {@link Money}. */
public enum Denomination {
    YUAN_100(10_000),
    YUAN_50(5_000),
    YUAN_20(2_000),
    YUAN_10(1_000);

    private final int cents;

    Denomination(int cents) {
        this.cents = cents;
    }

    public int cents() {
        return cents;
    }

    public static Denomination fromCents(int cents) {
        for (Denomination d : values()) {
            if (d.cents == cents) {
                return d;
            }
        }
        throw new IllegalArgumentException("unsupported denomination: " + cents);
    }
}
