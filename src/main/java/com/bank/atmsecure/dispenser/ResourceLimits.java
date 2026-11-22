package com.bank.atmsecure.dispenser;

/**
 * Resource envelope of the dispenser controller, and the defensive limits derived from it.
 *
 * <p>The MCU is assumed to be roughly a Cortex-M0+ class part: tens of KB of RAM, no MMU, a slow
 * asymmetric engine (a single Ed25519 verify costs meaningful milliseconds), NVRAM with finite write
 * endurance, and a clock that can be disturbed. Those constraints are not just performance notes —
 * each one is a denial-of-service lever for an attacker who owns the bus. So every limit below is
 * also a <em>budget</em> enforced by the module:
 *
 * <ul>
 *   <li>{@link #MAX_FRAME_BYTES}: bounds parsing memory; larger frames are dropped before allocation.</li>
 *   <li>{@link #MAX_VERIFY_PER_SECOND}: an attacker cannot pin the CPU with a flood of bogus
 *       signatures; beyond the budget the module answers {@code THROTTLED} without verifying.</li>
 *   <li>{@link #MAX_HELLO_PER_SECOND}: handshakes each cost the module one signature, so they are rate
 *       limited separately.</li>
 *   <li>{@link #MAX_NVRAM_COMMITS_PER_HOUR}: flash endurance protection. A dispense commits state; a
 *       flood of requests that each cause a commit would wear out NVRAM. Only <em>successful</em>
 *       physical dispenses consume this budget; refusals never write.</li>
 *   <li>{@link #MAX_CONSECUTIVE_AUTH_FAILURES}: after this many authorisation failures the module
 *       enters a cool-down and requires a service visit — brute-forcing signatures is not viable, but
 *       this stops an attacker using the module as a signing oracle / noise source.</li>
 * </ul>
 */
public final class ResourceLimits {
    public static final int MAX_FRAME_BYTES = 4096;
    public static final int MAX_VERIFY_PER_SECOND = 8;
    public static final int MAX_HELLO_PER_SECOND = 3;
    public static final int MAX_NVRAM_COMMITS_PER_HOUR = 600;
    public static final int MAX_CONSECUTIVE_AUTH_FAILURES = 20;
    public static final int MAX_PENDING_NONCES = 4;
    public static final long NONCE_LIFETIME_MILLIS = 30_000;

    private ResourceLimits() {
    }
}
