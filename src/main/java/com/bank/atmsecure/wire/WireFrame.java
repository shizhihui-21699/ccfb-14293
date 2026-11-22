package com.bank.atmsecure.wire;

import com.bank.atmsecure.crypto.Aead;
import com.bank.atmsecure.crypto.Canonical;
import com.bank.atmsecure.crypto.CryptoException;
import com.bank.atmsecure.model.Protocol;

/**
 * Encrypted, authenticated frame on the link.
 *
 * <pre>
 *   +--------+--------+--------+----------------+-------------------+------------------+
 *   | magic  | ver    | type   | sessionId (8)  | seq (8)           | ciphertext       |
 *   | 4 "ATMF"| 2      | 1      |                |                   | (GCM: body+tag)  |
 *   +--------+--------+--------+----------------+-------------------+------------------+
 *              \----------------- AAD ---------------------------------/
 * </pre>
 *
 * <p>The header is the AEAD associated data, so flipping the type, session or sequence number
 * invalidates the tag. The sequence number is also checked by the receiver (strictly increasing,
 * bounded jump) which rejects replayed frames even before decryption.
 *
 * <p>{@code sessionId} is derived from the handshake transcript; a frame from a different handshake
 * simply fails to open.
 */
public record WireFrame(int version, MessageType type, long sessionId, long seq, byte[] ciphertext) {
    public static final int HEADER_BYTES = 4 + 2 + 1 + 8 + 8;

    public byte[] headerBytes() {
        Canonical.Writer w = new Canonical.Writer();
        w.u32(Protocol.MAGIC);
        w.u16(version);
        w.u8(type.code());
        w.u64(sessionId);
        w.u64(seq);
        return w.toByteArray();
    }

    public byte[] encode() {
        return Canonical.concat(headerBytes(), ciphertext);
    }

    public static WireFrame decodeHeader(byte[] raw) {
        if (raw.length < HEADER_BYTES) {
            throw new ProtoException("frame shorter than header");
        }
        if (raw.length > Protocol.MAX_FRAME_BYTES) {
            throw new ProtoException("frame exceeds size limit");
        }
        Canonical.Reader r = new Canonical.Reader(raw);
        long magic = r.u32();
        if (magic != (Protocol.MAGIC & 0xffffffffL)) {
            throw new ProtoException("bad magic");
        }
        int version = r.u16();
        if (version != Protocol.VERSION) {
            throw new ProtoException("unsupported protocol version " + version);
        }
        int typeCode = r.u8();
        MessageType type;
        try {
            type = MessageType.fromCode(typeCode);
        } catch (IllegalArgumentException e) {
            throw new ProtoException("unknown message type " + typeCode);
        }
        long sessionId = r.u64();
        long seq = r.u64();
        int ctLen = raw.length - HEADER_BYTES;
        if (ctLen < Aead.TAG_BITS / 8) {
            throw new ProtoException("frame shorter than GCM tag");
        }
        byte[] ct = new byte[ctLen];
        System.arraycopy(raw, HEADER_BYTES, ct, 0, ctLen);
        return new WireFrame(version, type, sessionId, seq, ct);
    }

    public static WireFrame create(byte[] sessionKey, MessageType type, long sessionId, long seq,
            byte[] plaintext) {
        if (plaintext.length > Protocol.MAX_PLAINTEXT_BYTES) {
            throw new ProtoException("plaintext exceeds size limit");
        }
        WireFrame skeleton = new WireFrame(Protocol.VERSION, type, sessionId, seq, new byte[0]);
        byte[] aad = skeleton.headerBytes();
        byte[] nonce = Aead.derivedNonce(sessionKey, seq,
                (byte) (type.code() & 1)); // direction bit folded into type parity
        byte[] ct = Aead.seal(sessionKey, nonce, aad, plaintext);
        WireFrame out = new WireFrame(Protocol.VERSION, type, sessionId, seq, ct);
        if (out.encode().length > Protocol.MAX_FRAME_BYTES) {
            throw new ProtoException("sealed frame exceeds size limit");
        }
        return out;
    }

    public byte[] open(byte[] sessionKey) {
        byte[] aad = headerBytes();
        byte[] nonce = Aead.derivedNonce(sessionKey, seq, (byte) (type.code() & 1));
        try {
            byte[] pt = Aead.open(sessionKey, nonce, aad, ciphertext);
            if (pt.length > Protocol.MAX_PLAINTEXT_BYTES) {
                throw new ProtoException("plaintext exceeds size limit");
            }
            return pt;
        } catch (CryptoException e) {
            throw new ProtoException("frame authentication failed");
        }
    }
}
