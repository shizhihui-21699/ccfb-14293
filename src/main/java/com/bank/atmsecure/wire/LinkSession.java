package com.bank.atmsecure.wire;

import com.bank.atmsecure.crypto.Kdf;
import com.bank.atmsecure.crypto.X25519;
import com.bank.atmsecure.model.Protocol;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * A completed link session. Holds one ECDH agreement expanded (via HKDF) into <em>separate</em>
 * keys per direction, so a frame cannot be reflected back at its sender, and independent nonce
 * spaces never collide.
 *
 * <p>Roles matter: the terminal uses {@code termToDisp} to send and {@code dispToTerm} to receive;
 * the dispenser does the inverse. The role is fixed at construction.
 */
public final class LinkSession {
    public enum Role { TERMINAL, DISPENSER }

    private final Role role;
    private final byte[] sessionKey;
    private final byte[] termToDisp;
    private final byte[] dispToTerm;
    private final long sessionId;
    private final byte[] channelBinding;
    private long outboundSeq;
    private long highestInboundSeq;

    private LinkSession(Role role, byte[] sessionKey, byte[] t2d, byte[] d2t) {
        this.role = role;
        this.sessionKey = sessionKey;
        this.termToDisp = t2d;
        this.dispToTerm = d2t;
        this.sessionId = deriveSessionId(sessionKey);
        this.channelBinding = Kdf.hkdf(sessionKey, null, "authorization-channel-binding", 32);
    }

    public static LinkSession establish(Role role, KeyPair myEphemeral, PublicKey peerEphemeral,
            byte[] transcript) {
        byte[] shared = X25519.agree(myEphemeral.getPrivate(), peerEphemeral);
        byte[] master = Kdf.hkdf(shared, transcript, "link-session-key", 32);
        byte[] t2d = Kdf.hkdf(master, transcript, "term->disp", 32);
        byte[] d2t = Kdf.hkdf(master, transcript, "disp->term", 32);
        return new LinkSession(role, master, t2d, d2t);
    }

    public WireFrame seal(MessageType type, byte[] plaintext) {
        byte[] key = role == Role.TERMINAL ? termToDisp : dispToTerm;
        long seq = ++outboundSeq;
        return WireFrame.create(key, type, sessionId, seq, plaintext);
    }

    /** Opens an inbound frame, enforcing session id, forward-only sequence and the jump bound. */
    public byte[] open(WireFrame frame) {
        if (frame.sessionId() != sessionId) {
            throw new ProtoException("frame belongs to another session");
        }
        if (frame.seq() <= highestInboundSeq) {
            throw new ProtoException("replayed or reordered frame, seq " + frame.seq());
        }
        if (frame.seq() - highestInboundSeq > Protocol.MAX_SEQ_JUMP) {
            throw new ProtoException("inbound sequence jump too large");
        }
        byte[] key = role == Role.TERMINAL ? dispToTerm : termToDisp;
        byte[] pt = frame.open(key);
        highestInboundSeq = frame.seq();
        return pt;
    }

    public long sessionId() {
        return sessionId;
    }

    public byte[] channelBinding() {
        return channelBinding.clone();
    }

    public Role role() {
        return role;
    }

    public long highestInboundSeq() {
        return highestInboundSeq;
    }

    /** Test/diagnostic only: exposes key material to prove sessions are independent. */
    byte[] sessionKeyForTests() {
        return sessionKey.clone();
    }

    /** True when two sessions share neither master key nor channel binding (freshness check). */
    static boolean distinct(LinkSession a, LinkSession b) {
        return !Arrays.equals(a.sessionKey, b.sessionKey)
                && !Arrays.equals(a.channelBinding, b.channelBinding);
    }

    private static long deriveSessionId(byte[] sessionKey) {
        byte[] h = Kdf.sha256(com.bank.atmsecure.crypto.Canonical.domain("link-session-id")
                .bytes(sessionKey).toByteArray());
        long id = 0;
        for (int i = 0; i < 8; i++) {
            id = (id << 8) | (h[i] & 0xffL);
        }
        return id;
    }
}
