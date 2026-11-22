package com.bank.atmsecure.dispenser;

/**
 * Why a request was refused. Codes are stable and are what the module logs and (coarsely) reports.
 *
 * <p>The terminal-facing message deliberately collapses several causes into
 * {@link #AUTHORIZATION_REJECTED} so an attacker probing the bus cannot use the distinction between
 * "bad signature" and "stale sequence" as an oracle. The precise reason stays in the module's own
 * tamper-evident log.
 */
public enum DispenseStatus {
    OK(0),
    /** Any authorisation defect: signature, binding, epoch, plan, expiry. */
    AUTHORIZATION_REJECTED(1),
    /** Sequence number not strictly ahead of the persisted high-water mark. */
    STALE_SEQUENCE(2),
    /** The module's one-time challenge for this session was already used or never issued. */
    BAD_NONCE(3),
    /** Requested notes exceed cassette contents; nothing was dispensed. */
    INSUFFICIENT_CASH(4),
    /** Authorisation expired. */
    EXPIRED(5),
    /** Module is locked (tamper, rollback, service required). */
    MODULE_LOCKED(6),
    /** Rate/verify budget exhausted. */
    THROTTLED(7),
    /** Offline envelope exhausted or invalid. */
    OFFLINE_REFUSED(8),
    /** Physical transport fault — notes not confirmed delivered. */
    TRANSPORT_FAULT(9),
    /** Malformed request. */
    BAD_REQUEST(10);

    private final int code;

    DispenseStatus(int code) {
        this.code = code;
    }

    public int code() {
        return code;
    }

    public static DispenseStatus fromCode(int code) {
        for (DispenseStatus s : values()) {
            if (s.code == code) {
                return s;
            }
        }
        throw new IllegalArgumentException("unknown status " + code);
    }

    public boolean ok() {
        return this == OK;
    }
}
