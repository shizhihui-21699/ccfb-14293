package com.bank.atmsecure.model;

/** Protocol-wide constants. A version bump is a flag day; there is no plaintext legacy mode. */
public final class Protocol {
    public static final int VERSION = 1;
    public static final int MAGIC = 0x41544D46; // "ATMF"
    public static final int MAX_FRAME_BYTES = 4096;
    public static final int MAX_PLAINTEXT_BYTES = 3072;
    public static final int NONCE_BYTES = 16;
    public static final int HASH_BYTES = 32;
    public static final int LINK_KEY_BYTES = 32;
    public static final int CHANNEL_BINDING_BYTES = 32;

    /** Clock skew tolerated when checking authorisation validity, on top of the host grace. */
    public static final long CLOCK_SKEW_MILLIS = 5_000;

    /** A module will not skip more than this many sequence numbers in one hop. */
    public static final long MAX_SEQ_JUMP = 1_000;

    private Protocol() {
    }
}
