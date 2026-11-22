package com.bank.atmsecure.crypto;

/** Hex helpers used by diagnostics, audit output and tests. */
public final class Hex {
    private static final char[] DIG = "0123456789abcdef".toCharArray();

    private Hex() {
    }

    public static String encode(byte[] bytes) {
        if (bytes == null) {
            return "null";
        }
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xff;
            out[i * 2] = DIG[v >>> 4];
            out[i * 2 + 1] = DIG[v & 0x0f];
        }
        return new String(out);
    }

    public static String encode(byte[] bytes, int maxBytes) {
        if (bytes == null) {
            return "null";
        }
        if (bytes.length <= maxBytes) {
            return encode(bytes);
        }
        byte[] head = new byte[maxBytes];
        System.arraycopy(bytes, 0, head, 0, maxBytes);
        return encode(head) + "…(" + bytes.length + "B)";
    }

    public static byte[] decode(String s) {
        if ((s.length() & 1) != 0) {
            throw new IllegalArgumentException("odd hex length");
        }
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(s.charAt(i * 2), 16);
            int lo = Character.digit(s.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("bad hex at " + (i * 2));
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }
}
