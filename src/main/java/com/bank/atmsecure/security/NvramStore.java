package com.bank.atmsecure.security;

import com.bank.atmsecure.crypto.Canonical;
import com.bank.atmsecure.crypto.CryptoException;
import com.bank.atmsecure.crypto.Hex;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Model of the dispenser's bulk persistent store (a few KB of battery-backed SRAM).
 *
 * <p><b>This store is not trusted for security.</b> It models only what real NVRAM can offer: storage
 * with finite write endurance and a torn-write hazard. Security-critical monotonic state is anchored
 * in {@link OtpRegion} instead; this store merely mirrors it for speed and holds bulk data (cassette
 * levels, audit-log window, last receipt hash).
 *
 * <p>An attacker with a programmer can read and rewrite all of this. That is the point of the model:
 * the design must remain sound when every byte here is attacker-controlled, with rollback caught by
 * comparing against the OTP floor at boot ({@link RollbackProtectedCounter#bootFrom(long)}).
 *
 * <p>Torn writes are modelled A/B style: {@link #simulateTornWrite()} charges a program cycle but
 * leaves the committed map intact, representing the surviving good slot.
 */
public final class NvramStore {
    private final Map<String, byte[]> values = new LinkedHashMap<>();
    private long programCycles;

    public synchronized byte[] get(String key) {
        byte[] v = values.get(key);
        return v == null ? null : Arrays.copyOf(v, v.length);
    }

    public synchronized long getLong(String key, long defaultValue) {
        byte[] v = values.get(key);
        if (v == null || v.length != 8) {
            return defaultValue;
        }
        return RollbackProtectedCounter.bytesToLong(v);
    }

    public synchronized void put(String key, byte[] value) {
        values.put(key, Arrays.copyOf(value, value.length));
        programCycles++;
    }

    public synchronized void putLong(String key, long value) {
        put(key, RollbackProtectedCounter.longBytes(value));
    }

    public synchronized Map<String, byte[]> snapshot() {
        Map<String, byte[]> copy = new LinkedHashMap<>();
        values.forEach((k, v) -> copy.put(k, Arrays.copyOf(v, v.length)));
        return copy;
    }

    /** Replaces the whole map atomically in the model. */
    public synchronized void commit(Map<String, byte[]> newValues) {
        programCycles++;
        values.clear();
        new TreeMap<>(newValues).forEach((k, v) -> values.put(k, Arrays.copyOf(v, v.length)));
    }

    public synchronized long generation() {
        return programCycles;
    }

    public synchronized long programCyclesUsed() {
        return programCycles;
    }

    // ---------------------------------------------------------------------------------------------
    // Attacker hooks
    // ---------------------------------------------------------------------------------------------

    /** Captures a restorable image, exactly as a chip programmer would dump it. */
    public synchronized NvramImage captureImage() {
        return new NvramImage(programCycles, snapshot());
    }

    /** Restores a captured image. Whis is unconditionally allowed — rollback detection is at boot. */
    public synchronized void restoreImage(NvramImage image) {
        values.clear();
        image.values().forEach((k, v) -> values.put(k, Arrays.copyOf(v, v.length)));
        programCycles = image.programCycles();
    }

    /** Power loss mid-program: A/B slots mean the last committed generation survives. */
    public synchronized void simulateTornWrite() {
        programCycles++;
    }

    /** Full erase, as an attacker slurping and zeroing the chip. */
    public synchronized void wipe() {
        values.clear();
        programCycles = 0;
    }

    public static String describe(NvramStore s) {
        return "NVRAM[cycles=" + s.programCycles + " keys=" + s.values.size() + "]";
    }

    /** Diagnostically useful: a short digest of the whole store. */
    public synchronized String digest() {
        Canonical.Writer w = new Canonical.Writer();
        new TreeMap<>(values).forEach((k, v) -> {
            w.str(k);
            w.bytes(v);
        });
        return Hex.encode(com.bank.atmsecure.crypto.Kdf.sha256(w.toByteArray()), 6);
    }

    public record NvramImage(long programCycles, Map<String, byte[]> valuesCopy) {
        public Map<String, byte[]> values() {
            Map<String, byte[]> copy = new LinkedHashMap<>();
            valuesCopy.forEach((k, v) -> copy.put(k, Arrays.copyOf(v, v.length)));
            return copy;
        }
    }
}
