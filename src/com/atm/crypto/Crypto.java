package com.atm.crypto;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * 全部密码原语的唯一入口。刻意只使用对称算法：
 * AES-256-GCM（认证加密）、HMAC-SHA256（HKDF 与哈希链）、SHA-256。
 * 这些算法在带 AES 硬件加速的低端 MCU 上也可流畅运行，契合出钞模块弱算力约束。
 */
public final class Crypto {

    public static final int AES_KEY_LEN = 32;   // AES-256
    public static final int GCM_IV_LEN = 12;    // 96-bit nonce，GCM 推荐长度
    public static final int GCM_TAG_BITS = 128;

    private static final SecureRandom RNG = new SecureRandom();

    private Crypto() {
    }

    public static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    /** 常量时间比较，避免计时侧信道。 */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    public static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] p : parts) {
                md.update(p);
            }
            return md.digest();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }

    /**
     * RFC 5869 HKDF-Extract + Expand，salt 固定为全零（密钥区分度由 info 标签保证）。
     */
    public static byte[] hkdf(byte[] ikm, byte[] info, int outputLen) {
        try {
            // Extract
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(new byte[hmac.getMacLength()], "HmacSHA256"));
            byte[] prk = hmac.doFinal(ikm);
            // Expand
            hmac.init(new SecretKeySpec(prk, "HmacSHA256"));
            byte[] t = new byte[0];
            byte[] okm = new byte[outputLen];
            int pos = 0;
            byte counter = 1;
            while (pos < outputLen) {
                hmac.reset();
                hmac.update(t);
                hmac.update(info);
                hmac.update(counter);
                t = hmac.doFinal();
                int take = Math.min(t.length, outputLen - pos);
                System.arraycopy(t, 0, okm, pos, take);
                pos += take;
                counter++;
            }
            return okm;
        } catch (Exception e) {
            throw new IllegalStateException("HKDF failure", e);
        }
    }

    /**
     * AES-256-GCM 认证加密。返回 iv || ciphertext||tag。
     *
     * @param aad 附加认证数据（头部、计数器等不加密但必须防篡改的字段）
     */
    public static byte[] aesGcmSeal(byte[] key, byte[] aad, byte[] plaintext) {
        try {
            byte[] iv = randomBytes(GCM_IV_LEN);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, iv));
            if (aad != null) {
                cipher.updateAAD(aad);
            }
            byte[] ct = cipher.doFinal(plaintext);
            byte[] out = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ct, 0, out, iv.length, ct.length);
            return out;
        } catch (Exception e) {
            throw new IllegalStateException("GCM seal failure", e);
        }
    }

    /**
     * AES-256-GCM 解密并验证 tag。tag 错误抛出 {@link AuthFailureException}，
     * 调用方必须把该失败视为“帧来源非法/内容被篡改”，且不得推进任何安全状态。
     */
    public static byte[] aesGcmOpen(byte[] key, byte[] aad, byte[] sealed) {
        if (sealed == null || sealed.length <= GCM_IV_LEN) {
            throw new AuthFailureException("sealed frame too short");
        }
        try {
            byte[] iv = Arrays.copyOfRange(sealed, 0, GCM_IV_LEN);
            byte[] ct = Arrays.copyOfRange(sealed, GCM_IV_LEN, sealed.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, iv));
            if (aad != null) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(ct);
        } catch (Exception e) {
            throw new AuthFailureException("GCM authentication failed", e);
        }
    }

    /** 认证失败异常：任何捕获到它的协议层都必须静默丢弃该帧。 */
    public static class AuthFailureException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public AuthFailureException(String message) {
            super(message);
        }

        public AuthFailureException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
