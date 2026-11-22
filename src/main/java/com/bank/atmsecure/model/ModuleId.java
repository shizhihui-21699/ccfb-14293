package com.bank.atmsecure.model;

import java.util.regex.Pattern;

/** Stable identity of a cash-dispenser module. Printed on the module, certified by the host. */
public record ModuleId(String value) {
    private static final Pattern PATTERN = Pattern.compile("[A-Z0-9][A-Z0-9-]{3,31}");

    public ModuleId {
        if (value == null || !PATTERN.matcher(value).matches()) {
            throw new IllegalArgumentException("invalid module id: " + value);
        }
    }

    @Override
    public String toString() {
        return value;
    }
}
