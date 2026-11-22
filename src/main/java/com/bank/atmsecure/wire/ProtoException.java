package com.bank.atmsecure.wire;

/** Any framing/parsing/authentication failure on the link. Deliberately coarse: details stay local. */
public class ProtoException extends RuntimeException {
    public ProtoException(String message) {
        super(message);
    }

    public ProtoException(String message, Throwable cause) {
        super(message, cause);
    }
}
