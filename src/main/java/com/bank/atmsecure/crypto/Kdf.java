package com.bank.atmsecure.crypto;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** HKDF-SHA256 (RFC 5869) and HMAC-SHA256 helpers. */
public final class Kdf {
    private Kdf() {
    }

    public static byte[] hmacSha256(byte[] key, byte[]... parts) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            for (byte[] p : parts) {
                mac.update(p);
            }
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("HMAC failed", e);
        }
    }

    public static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] p : parts) {
                md.update(p);
            }
            return md.digest();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("SHA-256 failed", e);
        }
    }

    /** RFC 5869 HKDF-Extract+Expand with an explicit info string. */
    public static byte[] hkdf(byte[] ikm, byte[] salt, String info, int outLen) {
        if (outLen <= 0 || outLen > 255 * 32) {
            throw new IllegalArgumentException("bad HKDF output length " + outLen);
        }
        byte[] prk = hmacSha256(salt == null || salt.length == 0 ? new byte[32] : salt, ikm);
        byte[] infoBytes = info.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] out = new byte[outLen];
        byte[] t = new byte[0];
        int at = 0;
        for (int i = 1; at < outLen; i++) {
            byte[] block = hmacSha256(prk, t, infoBytes, new byte[] {(byte) i});
            int n = Math.min(block.length, outLen - at);
            System.arraycopy(block, 0, out, at, n);
            at += n;
            t = block;
        }
        return out;
    }
}
