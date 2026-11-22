package com.bank.atmsecure.crypto;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-256-GCM with the full frame header bound into the AAD, so a captured ciphertext cannot be
 * re-attributed to a different session, sequence number or message type.
 */
public final class Aead {
    public static final int KEY_BYTES = 32;
    public static final int NONCE_BYTES = 12;
    public static final int TAG_BITS = 128;

    private Aead() {
    }

    public static byte[] seal(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext) {
        if (key.length != KEY_BYTES) {
            throw new IllegalArgumentException("AES-GCM key must be 32 bytes");
        }
        if (nonce.length != NONCE_BYTES) {
            throw new IllegalArgumentException("GCM nonce must be 12 bytes");
        }
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            if (aad != null && aad.length > 0) {
                c.updateAAD(aad);
            }
            return c.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("GCM seal failed", e);
        }
    }

    /**
     * @throws CryptoException on tag failure — callers must not distinguish authentication failure
     *     from parsing failure in what they report on the wire.
     */
    public static byte[] open(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext) {
        if (key.length != KEY_BYTES) {
            throw new IllegalArgumentException("AES-GCM key must be 32 bytes");
        }
        if (nonce.length != NONCE_BYTES) {
            throw new IllegalArgumentException("GCM nonce must be 12 bytes");
        }
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            if (aad != null && aad.length > 0) {
                c.updateAAD(aad);
            }
            return c.doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("GCM authentication failed", e);
        }
    }

    /** Deterministic per-session nonces are derived, never random, so a truncated RNG cannot reuse one. */
    public static byte[] derivedNonce(byte[] sessionKey, long seq, byte direction) {
        byte[] n = Kdf.hmacSha256(sessionKey,
                Canonical.domain("nonce").u64(seq).u8(direction).toByteArray());
        byte[] out = new byte[NONCE_BYTES];
        System.arraycopy(n, 0, out, 0, NONCE_BYTES);
        return out;
    }

    public static byte[] randomNonce() {
        byte[] n = new byte[NONCE_BYTES];
        SecureRandomHolder.INSTANCE.nextBytes(n);
        return n;
    }

    private static final class SecureRandomHolder {
        static final SecureRandom INSTANCE = new SecureRandom();
    }
}
