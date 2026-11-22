package com.atm.bus;

import java.util.ArrayList;
import java.util.List;

/**
 * 物理总线帧（线缆上实际出现的字节形态）：
 * <pre>
 * magic(2) | version(1) | type(1) | sourceId(变长, 2B长度前缀) | counter(8) | sealedPayload(4B长度前缀)
 * </pre>
 * type/counter/sourceId 构成 GCM 的 AAD：头部不加密，但任何篡改都会导致 tag 校验失败。
 * 这是纯数据载体，不含任何可信状态——攻击者可以任意构造它。
 */
public final class BusFrame {

    public static final byte[] MAGIC = {0x41, 0x54}; // "AT"

    public final byte type;
    public final String sourceId;
    public final long counter;
    public final byte[] sealedPayload;

    public BusFrame(byte type, String sourceId, long counter, byte[] sealedPayload) {
        this.type = type;
        this.sourceId = sourceId;
        this.counter = counter;
        this.sealedPayload = sealedPayload;
    }

    public byte[] serialize() {
        byte[] src = sourceId.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] out = new byte[2 + 1 + 1 + 2 + src.length + 8 + 4 + sealedPayload.length];
        int p = 0;
        out[p++] = MAGIC[0];
        out[p++] = MAGIC[1];
        out[p++] = com.atm.protocol.Protocol.VERSION;
        out[p++] = type;
        out[p++] = (byte) ((src.length >>> 8) & 0xFF);
        out[p++] = (byte) (src.length & 0xFF);
        System.arraycopy(src, 0, out, p, src.length);
        p += src.length;
        for (int i = 7; i >= 0; i--) {
            out[p++] = (byte) (counter >>> (8 * i));
        }
        out[p++] = (byte) ((sealedPayload.length >>> 24) & 0xFF);
        out[p++] = (byte) ((sealedPayload.length >>> 16) & 0xFF);
        out[p++] = (byte) ((sealedPayload.length >>> 8) & 0xFF);
        out[p++] = (byte) (sealedPayload.length & 0xFF);
        System.arraycopy(sealedPayload, 0, out, p, sealedPayload.length);
        return out;
    }

    public static BusFrame parse(byte[] raw) {
        if (raw == null || raw.length < 14 || raw[0] != MAGIC[0] || raw[1] != MAGIC[1]) {
            throw new IllegalArgumentException("bad frame magic");
        }
        int p = 2;
        byte version = raw[p++];
        if (version != com.atm.protocol.Protocol.VERSION) {
            throw new IllegalArgumentException("unsupported version: " + version);
        }
        byte type = raw[p++];
        int srcLen = ((raw[p] & 0xFF) << 8) | (raw[p + 1] & 0xFF);
        p += 2;
        String src = new String(raw, p, srcLen, java.nio.charset.StandardCharsets.UTF_8);
        p += srcLen;
        long counter = 0;
        for (int i = 0; i < 8; i++) {
            counter = (counter << 8) | (raw[p++] & 0xFFL);
        }
        int payloadLen = ((raw[p] & 0xFF) << 24) | ((raw[p + 1] & 0xFF) << 16)
                | ((raw[p + 2] & 0xFF) << 8) | (raw[p + 3] & 0xFF);
        p += 4;
        if (p + payloadLen != raw.length) {
            throw new IllegalArgumentException("frame length mismatch");
        }
        byte[] payload = new byte[payloadLen];
        System.arraycopy(raw, p, payload, 0, payloadLen);
        return new BusFrame(type, src, counter, payload);
    }

    /** 构造 AAD：头部参与 GCM 认证。 */
    public byte[] aad() {
        return buildAad(type, sourceId, counter);
    }

    /** 与 {@link #aad()} 完全一致的静态构造，供密封方在构造帧对象之前计算 AAD。 */
    public static byte[] buildAad(byte type, String sourceId, long counter) {
        byte[] src = sourceId.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] out = new byte[4 + 2 + src.length + 8];
        int p = 0;
        out[p++] = MAGIC[0];
        out[p++] = MAGIC[1];
        out[p++] = com.atm.protocol.Protocol.VERSION;
        out[p++] = type;
        out[p++] = (byte) ((src.length >>> 8) & 0xFF);
        out[p++] = (byte) (src.length & 0xFF);
        System.arraycopy(src, 0, out, p, src.length);
        p += src.length;
        for (int i = 7; i >= 0; i--) {
            out[p++] = (byte) (counter >>> (8 * i));
        }
        return out;
    }

    public static List<BusFrame> deepCopyFrames(List<BusFrame> frames) {
        List<BusFrame> copy = new ArrayList<>();
        for (BusFrame f : frames) {
            copy.add(new BusFrame(f.type, f.sourceId, f.counter, f.sealedPayload.clone()));
        }
        return copy;
    }
}
