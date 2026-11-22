package com.bank.atmsecure.model;

import java.util.regex.Pattern;

/**
 * Logical terminal identity, assigned by the bank and bound into every host authorisation.
 *
 * <p>It is intentionally <em>not</em> a security boundary on its own: the PC carrying the business
 * software can be swapped, and a clone would carry the same id. Binding it still lets the host and
 * the module refuse authorisations minted for a different ATM, and makes audits meaningful.
 */
public record TerminalId(String value) {
    private static final Pattern PATTERN = Pattern.compile("[A-Z0-9][A-Z0-9-]{2,31}");

    public TerminalId {
        if (value == null || !PATTERN.matcher(value).matches()) {
            throw new IllegalArgumentException("invalid terminal id: " + value);
        }
    }

    @Override
    public String toString() {
        return value;
    }
}
