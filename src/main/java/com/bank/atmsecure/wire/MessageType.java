package com.bank.atmsecure.wire;

/** Message types on the terminal↔dispenser link. Unknown/invalid types are rejected at parse. */
public enum MessageType {
    HELLO(0x01),
    HELLO_ACK(0x02),
    AUTH(0x03),
    AUTH_RESULT(0x04),
    DISPENSE(0x05),
    DISPENSE_RESULT(0x06),
    STATUS(0x07),
    STATUS_RESULT(0x08),
    RESYNC(0x09),
    RESYNC_RESULT(0x0A),
    BYE(0x0B),
    BYE_ACK(0x0C),
    ERROR(0x0F);

    private final int code;

    MessageType(int code) {
        this.code = code;
    }

    public int code() {
        return code;
    }

    public static MessageType fromCode(int code) {
        for (MessageType t : values()) {
            if (t.code == code) {
                return t;
            }
        }
        throw new IllegalArgumentException("unknown message type " + code);
    }
}
