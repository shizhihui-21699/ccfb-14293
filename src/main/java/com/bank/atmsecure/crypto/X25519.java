package com.bank.atmsecure.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;

/**
 * X25519 key agreement for the terminal↔dispenser link.
 *
 * <p>The link is deliberately built on <em>ephemeral</em> keys on both ends: the dispenser generates
 * its ephemeral keypair per session inside its own tamper-responding boundary. The session key is not
 * the trust anchor — it only prevents passive sniffing and replay/injection inside a live session.
 * Authorisation always comes from the host signature carried in the dispense message, so a stolen
 * terminal (or a substituted PC) cannot mint money even though it can complete the handshake.
 */
public final class X25519 {
    public static final int KEY_BYTES = 32;

    private X25519() {
    }

    public static KeyPair generate() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("X25519");
            g.initialize(NamedParameterSpec.X25519);
            return g.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("JDK lacks X25519", e);
        }
    }

    public static byte[] agree(java.security.PrivateKey mine, PublicKey theirs) {
        try {
            KeyAgreement ka = KeyAgreement.getInstance("X25519");
            ka.init(mine);
            ka.doPhase(theirs, true);
            byte[] secret = ka.generateSecret();
            // Reject the all-zero shared secret arising from a low-order public key.
            if (isAllZero(secret)) {
                throw new CryptoException("X25519 produced low-order point / zero secret");
            }
            return secret;
        } catch (GeneralSecurityException e) {
            throw new CryptoException("X25519 agree failed", e);
        }
    }

    public static byte[] rawPublic(PublicKey key) {
        byte[] der = key.getEncoded();
        byte[] raw = new byte[KEY_BYTES];
        System.arraycopy(der, der.length - KEY_BYTES, raw, 0, KEY_BYTES);
        return raw;
    }

    public static PublicKey fromRawPublic(byte[] raw) {
        if (raw == null || raw.length != KEY_BYTES) {
            throw new CryptoException("raw X25519 key must be 32 bytes");
        }
        byte[] prefix = new byte[] {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00
        };
        try {
            return KeyFactory.getInstance("X25519")
                    .generatePublic(new X509EncodedKeySpec(Canonical.concat(prefix, raw)));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("bad raw X25519 key", e);
        }
    }

    private static boolean isAllZero(byte[] b) {
        int acc = 0;
        for (byte x : b) {
            acc |= x;
        }
        return acc == 0;
    }
}
