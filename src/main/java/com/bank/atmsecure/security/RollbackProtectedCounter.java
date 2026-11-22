package com.bank.atmsecure.security;

import com.bank.atmsecure.crypto.CryptoException;

/**
 * A monotonic counter whose value is anchored in {@link OtpRegion}, so a rollback of its NVRAM mirror
 * is detected and latched rather than silently accepted.
 *
 * <p>Two failure modes are modelled and both fail closed:
 * <ul>
 *   <li><b>Rollback.</b> An attacker restores an old NVRAM image. The reloaded value is below the OTP
 *       floor; {@link #bootFrom(long)} latches tamper.</li>
 *   <li><b>Exhaustion.</b> The OTP bank is full. An unanchored increment is refused rather than
 *       allowed to proceed on rewritable storage alone.</li>
 * </ul>
 *
 * <p>The counter is the basis of offline spending: the module's remaining offline budget is derived
 * from {@code (envelope base, current value)} where the base and the current value are both
 * OTP-anchored, so rolling NVRAM back cannot mint budget. See
 * {@link CashDispenserModule#dispenseOffline}.
 */
public final class RollbackProtectedCounter {
    private final String name;
    private final OtpRegion otp;
    private long value;
    private boolean tampered;
    private String tamperReason;

    public RollbackProtectedCounter(String name, OtpRegion otp) {
        this.name = name;
        this.otp = otp;
        this.value = otp.floor();
    }

    public synchronized long value() {
        if (tampered) {
            throw new CryptoException(name + " counter tampered: " + tamperReason);
        }
        return value;
    }

    public synchronized long peek() {
        return value;
    }

    public synchronized long otpFloor() {
        return otp.floor();
    }

    public synchronized boolean isTampered() {
        return tampered;
    }

    public synchronized String tamperReason() {
        return tamperReason;
    }

    /**
     * Validates a value reloaded from NVRAM against the OTP floor at boot.
     *
     * @throws CryptoException on rollback (the counter latches tamper).
     */
    public synchronized long bootFrom(long nvramValue) {
        if (tampered) {
            throw new CryptoException(name + " counter tampered: " + tamperReason);
        }
        if (nvramValue < otp.floor()) {
            latch("NVRAM value " + nvramValue + " below OTP floor " + otp.floor());
            throw new CryptoException(tamperReason);
        }
        value = nvramValue;
        return value;
    }

    /**
     * Advances the counter by {@code delta} (must be > 0) and burns the new value into OTP.
     *
     * <p>Ordering contract with the caller, chosen so a crash at any point is safe:
     * <ol>
     *   <li>caller persists the new value to NVRAM first (the mirror catches up to {@code next});</li>
     *   <li>caller then calls this method, which burns OTP;</li>
     *   <li>only then does the caller make the guarded effect (cash movement) visible.</li>
     * </ol>
     * A crash before step 2 leaves NVRAM {@code >=} the OTP floor (no false tamper) and the anchor
     * slightly behind — still monotone. A crash after step 3 leaves both advanced. The invariant that
     * matters, {@code NVRAM >= OTP floor}, therefore always holds on an honest power loss, so a boot
     * that sees {@code NVRAM < floor} can only mean an attacker rewound NVRAM.
     *
     * <p>Note the residual effect: a crash between steps 2 and 3 burns an anchor without moving cash,
     * which can refuse a later legitimate spend but can never grant one. That is the correct direction
     * to fail.
     *
     * @throws CryptoException if tampered or the OTP bank is exhausted.
     */
    public synchronized long incrementBy(long delta) {
        if (tampered) {
            throw new CryptoException(name + " counter tampered: " + tamperReason);
        }
        if (delta <= 0) {
            throw new IllegalArgumentException("delta must be positive");
        }
        long next = value + delta;
        if (!otp.tryBurn(next)) {
            latch("OTP bank exhausted anchoring " + name + " at " + next);
            throw new CryptoException(tamperReason);
        }
        value = next;
        return value;
    }

    public synchronized long increment() {
        return incrementBy(1);
    }

    /**
     * Advances the in-memory value to {@code target} <em>without</em> burning OTP. The caller is
     * expected to persist the mirror and then call {@link #anchor(long)} in the same commit window, in
     * the order documented on {@link #incrementBy(long)}. Used when a single dispense advances the
     * counter by an amount decided up front (offline cumulative spend) and we want both the NVRAM and
     * the OTP write to reflect the same final value.
     */
    public synchronized void setValue(long target) {
        if (tampered) {
            throw new CryptoException(name + " counter tampered: " + tamperReason);
        }
        if (target < value) {
            throw new IllegalArgumentException("counter cannot move backwards: " + target + " < "
                    + value);
        }
        value = target;
    }

    /** Burns the current value into OTP. No-op if already anchored at {@code value}. */
    public synchronized long anchor() {
        if (tampered) {
            throw new CryptoException(name + " counter tampered: " + tamperReason);
        }
        if (value <= otp.floor()) {
            return value; // already anchored, nothing to burn
        }
        if (!otp.tryBurn(value)) {
            latch("OTP bank exhausted anchoring " + name + " at " + value);
            throw new CryptoException(tamperReason);
        }
        return value;
    }

    /** Attacker rewinds the backing store; latches tamper if it crosses the OTP floor. */
    public synchronized void restoreValue(long restored) {
        if (tampered) {
            return;
        }
        if (restored < otp.floor()) {
            latch("counter rolled back to " + restored + " (OTP floor " + otp.floor() + ")");
            return;
        }
        value = restored;
    }

    /** Service jumper: clears a tamper latch and re-anchors at the current OTP floor. */
    public synchronized void clearByServiceJumper(String technicianId) {
        tampered = false;
        tamperReason = null;
        value = Math.max(value, otp.floor());
    }

    private void latch(String reason) {
        tampered = true;
        tamperReason = reason;
    }

    public static byte[] longBytes(long v) {
        byte[] b = new byte[8];
        for (int i = 7; i >= 0; i--) {
            b[i] = (byte) (v & 0xff);
            v >>>= 8;
        }
        return b;
    }

    public static long bytesToLong(byte[] b) {
        long out = 0;
        for (byte x : b) {
            out = (out << 8) | (x & 0xffL);
        }
        return out;
    }

    @Override
    public synchronized String toString() {
        return name + "[value=" + value + " " + otp.describe()
                + (tampered ? " TAMPER(" + tamperReason + ")" : "") + "]";
    }
}
