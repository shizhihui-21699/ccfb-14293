package com.bank.atmsecure.wire;

import com.bank.atmsecure.crypto.Canonical;
import com.bank.atmsecure.crypto.CryptoException;
import com.bank.atmsecure.model.Protocol;

/**
 * Plaintext HELLO. Contains the terminal's ephemeral public key and a random value.
 *
 * <p>It is the only plaintext message besides HELLO_ACK, and it carries no secret. Everything after
 * it is a sealed {@link WireFrame}.
 */
public record Hello(byte[] terminalEphemeralPublic, byte[] terminalRandom, String terminalSoftware,
        int protocolVersion) {

    public byte[] encode() {
        Canonical.Writer w = new Canonical.Writer();
        w.u16(protocolVersion);
        w.bytes(terminalEphemeralPublic);
        w.bytes(terminalRandom);
        w.str(truncate(terminalSoftware, 64));
        return w.toByteArray();
    }

    public static Hello decode(byte[] raw) {
        if (raw.length > Protocol.MAX_FRAME_BYTES) {
            throw new ProtoException("HELLO too large");
        }
        Canonical.Reader r = new Canonical.Reader(raw);
        int ver = r.u16();
        byte[] pub = r.bytes();
        byte[] rnd = r.bytes();
        String sw = r.str();
        r.expectEnd();
        if (pub.length != 32) {
            throw new ProtoException("HELLO ephemeral key wrong length");
        }
        if (rnd.length < 16 || rnd.length > 64) {
            throw new ProtoException("HELLO random wrong length");
        }
        return new Hello(pub, rnd, sw, ver);
    }

    static String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max);
    }
}
