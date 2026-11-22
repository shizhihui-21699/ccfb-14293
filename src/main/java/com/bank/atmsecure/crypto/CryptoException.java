package com.bank.atmsecure.crypto;

/**
 * Raised for any cryptographic failure: bad signature, failed AEAD tag, malformed key material.
 * Callers must treat this as a security event and fail closed — never retry with weaker options.
 */
public class CryptoException extends RuntimeException {
    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
