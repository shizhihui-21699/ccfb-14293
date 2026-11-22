package com.bank.atmsecure.security;

import com.bank.atmsecure.crypto.CryptoException;
import com.bank.atmsecure.crypto.Hex;

/**
 * Model of the MCU's one-time-programmable fuse bank: the only storage a chip-off attacker cannot
 * rewind.
 *
 * <p>Real OTP is <em>readable</em> and can be written exactly once per bit. That makes it the natural
 * home for a monotonic counter: each slot holds a 64-bit value that must be strictly greater than
 * every value already burned. Reading the bank recovers the highest floor even after power loss, and
 * no amount of NVRAM tampering can lower it.
 *
 * <p>Capacity is finite and burning is permanent, so slots are a scarce resource. High-volume,
 * low-value state must not live here; only rare, security-critical events do (offline spends,
 * re-pairings, epoch changes). When the bank fills, operations that need an anchor fail closed.
 */
public final class OtpRegion {
    private final String name;
    private final int capacity;
    private long[] slots;
    private int used;
    private boolean exhausted;

    public OtpRegion(String name, int capacity) {
        if (capacity < 1) {
            throw new IllegalArgumentException("OTP capacity must be positive");
        }
        this.name = name;
        this.capacity = capacity;
        this.slots = new long[Math.min(capacity, 64)];
    }

    /**
     * Burns {@code value} into the next slot. The value must strictly exceed the current floor, which
     * mirrors hardware where a fuse can only move 0→1.
     *
     * @return false if the bank is full (caller must fail closed), true on success.
     */
    public synchronized boolean tryBurn(long value) {
        if (used >= capacity) {
            exhausted = true;
            return false;
        }
        if (value <= floor()) {
            throw new CryptoException("OTP " + name + " is append-only; " + value
                    + " does not exceed floor " + floor());
        }
        burn(value);
        return true;
    }

    /**
     * Seeds the very first value (the factory anchor). Permits 0, which is otherwise not a legal burn
     * because it does not exceed the pristine floor of 0.
     */
    public synchronized void seed(long value) {
        if (used != 0) {
            throw new CryptoException("OTP " + name + " already seeded");
        }
        burn(value);
    }

    private void burn(long value) {
        if (used == slots.length) {
            slots = java.util.Arrays.copyOf(slots, Math.min(capacity, slots.length * 2));
        }
        slots[used++] = value;
    }

    /** Highest value burned so far, or 0 for a pristine bank. This is the rollback floor. */
    public synchronized long floor() {
        return used == 0 ? 0L : slots[used - 1];
    }

    public synchronized boolean isExhausted() {
        return exhausted;
    }

    public synchronized int used() {
        return used;
    }

    public synchronized int capacity() {
        return capacity;
    }

    public synchronized String describe() {
        return "OTP[" + name + " " + used + "/" + capacity + " floor=" + floor()
                + (exhausted ? " EXHAUSTED" : "") + "]";
    }

    /** Simulates physical inspection: the readable bank. */
    public synchronized long[] readableSlots() {
        return java.util.Arrays.copyOf(slots, used);
    }

    public synchronized String srFingerprint() {
        return Hex.encode(com.bank.atmsecure.crypto.Kdf.sha256(
                com.bank.atmsecure.crypto.Canonical.domain("otp-sr").str(name)
                        .u64(floor()).u32(used).toByteArray()), 6);
    }
}
