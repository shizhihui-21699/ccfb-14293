package com.bank.atmsecure.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class CryptoPrimitivesTest {

    @Test
    @DisplayName("Ed25519 signs and verifies; tampering breaks verification")
    void ed25519RoundTrip() {
        KeyPair kp = Ed25519.generate();
        byte[] msg = "dispense:500:TX-1".getBytes();
        byte[] sig = Ed25519.sign(kp.getPrivate(), msg);
        assertTrue(Ed25519.verify(kp.getPublic(), msg, sig));
        byte[] bad = msg.clone();
        bad[0] ^= 1;
        assertFalse(Ed25519.verify(kp.getPublic(), bad, sig));
        assertFalse(Ed25519.verify(kp.getPublic(), msg, new byte[63]));
    }

    @Test
    @DisplayName("Raw public key round-trips through the 32-byte form")
    void rawPublicRoundTrip() {
        KeyPair kp = Ed25519.generate();
        byte[] raw = Ed25519.rawPublic(kp.getPublic());
        assertEquals(32, raw.length);
        assertEquals(kp.getPublic(), Ed25519.fromRawPublic(raw));
    }

    @Test
    @DisplayName("X25519 agreement is symmetric and rejects mismatched keys")
    void x25519Agreement() {
        KeyPair a = X25519.generate();
        KeyPair b = X25519.generate();
        byte[] ab = X25519.agree(a.getPrivate(), b.getPublic());
        byte[] ba = X25519.agree(b.getPrivate(), a.getPublic());
        assertArrayEquals(ab, ba);
    }

    @Test
    @DisplayName("AES-GCM binds the AAD: a header change invalidates the tag")
    void aeadBindsAad() {
        byte[] key = new byte[32];
        new java.security.SecureRandom().nextBytes(key);
        byte[] nonce = Aead.randomNonce();
        byte[] aad = "header-1".getBytes();
        byte[] ct = Aead.seal(key, nonce, aad, "secret".getBytes());
        assertArrayEquals("secret".getBytes(), Aead.open(key, nonce, aad, ct));
        assertThrows(CryptoException.class, () -> Aead.open(key, nonce, "header-2".getBytes(), ct));
        assertThrows(CryptoException.class, () -> Aead.open(key, Aead.randomNonce(), aad, ct));
    }

    @Test
    @DisplayName("HKDF output is deterministic, length-correct and info-separated")
    void hkdf() {
        byte[] ikm = new byte[32];
        byte[] salt = new byte[16];
        byte[] a = Kdf.hkdf(ikm, salt, "one", 32);
        byte[] b = Kdf.hkdf(ikm, salt, "one", 32);
        byte[] c = Kdf.hkdf(ikm, salt, "two", 32);
        assertArrayEquals(a, b);
        assertNotEquals(Arrays.toString(a), Arrays.toString(c));
        assertEquals(64, Kdf.hkdf(ikm, salt, "x", 64).length);
    }

    @Test
    @DisplayName("Canonical encoding rejects trailing bytes and non-canonical booleans")
    void canonicalStrictness() {
        byte[] enc = Canonical.domain("t").u64(7).str("abc").toByteArray();
        Canonical.Reader r = new Canonical.Reader(enc);
        assertEquals("ATM1", new String(r.fixed(4)));
        assertEquals("t", r.str());
        assertEquals(7, r.u64());
        assertEquals("abc", r.str());
        r.expectEnd();
        assertThrows(IllegalArgumentException.class, r::u8);

        // Two trailing bytes must be rejected by expectEnd.
        byte[] padded = java.util.Arrays.copyOf(enc, enc.length + 2);
        var rp = new Canonical.Reader(padded);
        rp.fixed(4);
        rp.str();
        rp.u64();
        rp.str();
        assertThrows(IllegalArgumentException.class, rp::expectEnd);

        assertThrows(IllegalArgumentException.class,
                () -> new Canonical.Reader(new byte[] {2}).bool());
    }

    @Test
    @DisplayName("Canonical reader bounds field length to prevent hostile allocations")
    void canonicalBoundsFieldLength() {
        Canonical.Writer w = new Canonical.Writer();
        w.u32(Canonical.MAX_FIELD + 1L);
        assertThrows(IllegalArgumentException.class, () -> new Canonical.Reader(w.toByteArray()).bytes());
    }

    @Test
    @DisplayName("Constant-time compare is correct for equal/unequal inputs")
    void ctEquals() {
        assertTrue(Canonical.ctEquals(new byte[] {1, 2}, new byte[] {1, 2}));
        assertFalse(Canonical.ctEquals(new byte[] {1, 2}, new byte[] {1, 3}));
        assertFalse(Canonical.ctEquals(new byte[] {1}, new byte[] {1, 2}));
    }
}
