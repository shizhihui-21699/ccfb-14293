package com.bank.atmsecure.crypto;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Canonical, length-prefixed binary encoding used for everything that gets signed or MACed.
 *
 * <p>Why not JSON: signature verification must be bit-exact. Serialisation ambiguity (duplicate keys,
 * number formatting, whitespace, unknown fields) is a classic source of signature-bypass bugs. Every
 * structure here is written field-by-field by the signer and re-wrapped by the verifier from parsed
 * primitive values, so {@code encode(decode(x)) == x} for all accepted inputs.
 *
 * <p>All integers are big-endian fixed width. Byte strings are length-prefixed with a 4-byte length
 * and bounded on read so a hostile peer cannot make us allocate gigabytes.
 */
public final class Canonical {
    /** Hard ceiling for any single field. Dispense messages never legitimately exceed this. */
    public static final int MAX_FIELD = 64 * 1024;

    private Canonical() {
    }

    public static final class Writer {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream(256);

        public Writer u8(int v) {
            out.write(v & 0xff);
            return this;
        }

        public Writer u16(int v) {
            out.write((v >>> 8) & 0xff);
            out.write(v & 0xff);
            return this;
        }

        public Writer u32(long v) {
            out.write((int) (v >>> 24) & 0xff);
            out.write((int) (v >>> 16) & 0xff);
            out.write((int) (v >>> 8) & 0xff);
            out.write((int) v & 0xff);
            return this;
        }

        public Writer u64(long v) {
            for (int shift = 56; shift >= 0; shift -= 8) {
                out.write((int) (v >>> shift) & 0xff);
            }
            return this;
        }

        public Writer bool(boolean b) {
            return u8(b ? 1 : 0);
        }

        public Writer bytes(byte[] b) {
            if (b == null) {
                throw new IllegalArgumentException("null byte[] field");
            }
            if (b.length > MAX_FIELD) {
                throw new IllegalArgumentException("field too long: " + b.length);
            }
            u32(b.length);
            out.write(b, 0, b.length);
            return this;
        }

        public Writer raw(byte[] b) {
            out.write(b, 0, b.length);
            return this;
        }

        public Writer str(String s) {
            return bytes(s.getBytes(StandardCharsets.UTF_8));
        }

        public byte[] toByteArray() {
            return out.toByteArray();
        }

        public int size() {
            return out.size();
        }
    }

    public static final class Reader {
        private final ByteBuffer buf;

        public Reader(byte[] data) {
            this.buf = ByteBuffer.wrap(data);
        }

        public int u8() {
            need(1);
            return buf.get() & 0xff;
        }

        public int u16() {
            need(2);
            return buf.getShort() & 0xffff;
        }

        public long u32() {
            need(4);
            return buf.getInt() & 0xffffffffL;
        }

        public long u64() {
            need(8);
            return buf.getLong();
        }

        public boolean bool() {
            int v = u8();
            if (v != 0 && v != 1) {
                throw new IllegalArgumentException("non-canonical boolean: " + v);
            }
            return v == 1;
        }

        public byte[] bytes() {
            long len = u32();
            if (len > MAX_FIELD) {
                throw new IllegalArgumentException("field length out of range: " + len);
            }
            need((int) len);
            byte[] out = new byte[(int) len];
            buf.get(out);
            return out;
        }

        public byte[] fixed(int len) {
            need(len);
            byte[] out = new byte[len];
            buf.get(out);
            return out;
        }

        public String str() {
            return new String(bytes(), StandardCharsets.UTF_8);
        }

        public void expectEnd() {
            if (buf.hasRemaining()) {
                throw new IllegalArgumentException("trailing bytes after canonical structure: "
                        + buf.remaining());
            }
        }

        public boolean atEnd() {
            return !buf.hasRemaining();
        }

        private void need(int n) {
            if (buf.remaining() < n) {
                throw new IllegalArgumentException("truncated canonical structure: need " + n
                        + " have " + buf.remaining());
            }
        }
    }

    /** Domain separation prefix: "ATM1" + purpose UTF-8. Prevents cross-protocol signature reuse. */
    public static Writer domain(String purpose) {
        Writer w = new Writer();
        w.raw(new byte[] {'A', 'T', 'M', '1'});
        w.str(purpose);
        return w;
    }

    public static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) {
            total += p.length;
        }
        byte[] out = new byte[total];
        int at = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, at, p.length);
            at += p.length;
        }
        return out;
    }

    /** Constant-time comparison. */
    public static boolean ctEquals(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) {
            return false;
        }
        return java.security.MessageDigest.isEqual(a, b);
    }

    public static byte[] copy(byte[] b) {
        return b == null ? null : Arrays.copyOf(b, b.length);
    }
}
