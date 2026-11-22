package com.bank.atmsecure.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Ed25519 signatures.
 *
 * <p>Ed25519 is used for everything the low-power dispenser has to verify. The dispenser only ever
 * holds a <em>public</em> key, so dumping its flash yields no signing capability, and verification is
 * cheap and constant-time in the JDK implementation — a real dispenser MCU would use a small
 * curve25519 library with the same guarantees.
 *
 * <p>Signing keys live only in the {@code HostHsm} model: private key material is never exposed to
 * the terminal, the dispenser, or the wire.
 */
public final class Ed25519 {
    public static final int PUBLIC_KEY_BYTES = 32;
    public static final int SIGNATURE_BYTES = 64;

    private Ed25519() {
    }

    public static KeyPair generate() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("JDK lacks Ed25519", e);
        }
    }

    public static byte[] sign(PrivateKey key, byte[] message) {
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initSign(key);
            s.update(message);
            return s.sign();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Ed25519 sign failed", e);
        }
    }

    public static boolean verify(PublicKey key, byte[] message, byte[] signature) {
        if (key == null || message == null || signature == null
                || signature.length != SIGNATURE_BYTES) {
            return false;
        }
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initVerify(key);
            s.update(message);
            return s.verify(signature);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    public static byte[] encodePublic(PublicKey key) {
        // X.509 SubjectPublicKeyInfo; the raw 32 bytes are the tail. We store the full DER so it
        // round-trips through KeyFactory without hand-rolled parsing.
        return key.getEncoded();
    }

    public static byte[] encodePrivate(PrivateKey key) {
        return key.getEncoded();
    }

    public static PublicKey decodePublic(byte[] der) {
        try {
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("bad Ed25519 public key", e);
        }
    }

    public static PrivateKey decodePrivate(byte[] der) {
        try {
            return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("bad Ed25519 private key", e);
        }
    }

    /** Raw 32-byte public key, for compact on-wire formats. */
    public static byte[] rawPublic(PublicKey key) {
        byte[] der = key.getEncoded();
        byte[] raw = new byte[PUBLIC_KEY_BYTES];
        System.arraycopy(der, der.length - PUBLIC_KEY_BYTES, raw, 0, PUBLIC_KEY_BYTES);
        return raw;
    }

    public static PublicKey fromRawPublic(byte[] raw) {
        if (raw == null || raw.length != PUBLIC_KEY_BYTES) {
            throw new CryptoException("raw Ed25519 key must be 32 bytes");
        }
        // Wrap the raw point in a SubjectPublicKeyInfo for Ed25519 (OID 1.3.101.112).
        byte[] prefix = new byte[] {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
        };
        return decodePublic(Canonical.concat(prefix, raw));
    }
}
