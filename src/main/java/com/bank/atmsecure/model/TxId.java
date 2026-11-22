package com.bank.atmsecure.model;

import java.util.regex.Pattern;

/** Bank-side transaction reference. Unique per dispense, quoted on receipts and in reconciliation. */
public record TxId(String value) {
    private static final Pattern PATTERN = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{2,63}");

    public TxId {
        if (value == null || !PATTERN.matcher(value).matches()) {
            throw new IllegalArgumentException("invalid transaction id: " + value);
        }
    }

    @Override
    public String toString() {
        return value;
    }
}
