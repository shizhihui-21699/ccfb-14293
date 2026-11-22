package com.atm.protocol;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 极简 TLV 编解码：tag(1B) || length(2B, 大端) || value。
 * 所有应用层消息先编码成 TLV，再交给安全通道做 GCM 封装。
 */
public final class Tlv {

    public static final int MAX_LEN = 0xFFFF;

    private Tlv() {
    }

    public static byte[] encode(Map<Integer, byte[]> fields) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Map.Entry<Integer, byte[]> e : fields.entrySet()) {
            int tag = e.getKey();
            byte[] v = e.getValue();
            if (tag < 0 || tag > 255) {
                throw new IllegalArgumentException("tag must fit in one byte: " + tag);
            }
            if (v.length > MAX_LEN) {
                throw new IllegalArgumentException("value too long: " + v.length);
            }
            out.write(tag);
            out.write((v.length >>> 8) & 0xFF);
            out.write(v.length & 0xFF);
            out.write(v, 0, v.length);
        }
        return out.toByteArray();
    }

    public static Map<Integer, byte[]> decode(byte[] data) {
        Map<Integer, byte[]> fields = new LinkedHashMap<>();
        int pos = 0;
        while (pos < data.length) {
            if (pos + 3 > data.length) {
                throw new IllegalArgumentException("truncated TLV header");
            }
            int tag = data[pos] & 0xFF;
            int len = ((data[pos + 1] & 0xFF) << 8) | (data[pos + 2] & 0xFF);
            pos += 3;
            if (pos + len > data.length) {
                throw new IllegalArgumentException("truncated TLV value");
            }
            byte[] v = new byte[len];
            System.arraycopy(data, pos, v, 0, len);
            pos += len;
            fields.put(tag, v);
        }
        return fields;
    }

    public static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    public static String asUtf8(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }

    public static byte[] longBytes(long v) {
        byte[] b = new byte[8];
        for (int i = 7; i >= 0; i--) {
            b[i] = (byte) (v & 0xFF);
            v >>>= 8;
        }
        return b;
    }

    public static long asLong(byte[] b) {
        if (b == null || b.length != 8) {
            throw new IllegalArgumentException("expected 8-byte integer");
        }
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (b[i] & 0xFFL);
        }
        return v;
    }

    public static byte[] intBytes(int v) {
        return new byte[] {
                (byte) ((v >>> 24) & 0xFF),
                (byte) ((v >>> 16) & 0xFF),
                (byte) ((v >>> 8) & 0xFF),
                (byte) (v & 0xFF)
        };
    }

    public static int asInt(byte[] b) {
        if (b == null || b.length != 4) {
            throw new IllegalArgumentException("expected 4-byte integer");
        }
        return ((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16) | ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
    }

    public static Map<Integer, byte[]> builder() {
        return new LinkedHashMap<>();
    }
}
