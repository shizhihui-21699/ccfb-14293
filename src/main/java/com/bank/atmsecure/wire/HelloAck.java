package com.bank.atmsecure.wire;

import com.bank.atmsecure.crypto.Canonical;
import com.bank.atmsecure.crypto.CryptoException;
import com.bank.atmsecure.crypto.Ed25519;
import com.bank.atmsecure.model.ModuleId;
import com.bank.atmsecure.model.Protocol;
import com.bank.atmsecure.model.TerminalId;
import java.security.PublicKey;

/**
 * Dispenser's answer to HELLO. Carries the dispenser's ephemeral key, a random value for the
 * transcript, its identity/pairing state, and a signature over the full transcript made with the
 * certified module key.
 *
 * <p>The signed block is exactly {@link #signedTranscript()}; the terminal reconstructs it from
 * parsed fields, which is why every field is length-prefixed and bounded.
 */
public record HelloAck(byte[] moduleEphemeralPublic, byte[] moduleRandom, ModuleId moduleId,
        TerminalId pairedTerminalId, int keyEpoch, long dispenseSeqHighWater, boolean serviceMode,
        int statusCode, byte[] signature) {

    public static final int STATUS_OK = 0;
    public static final int STATUS_NOT_PAIRED = 1;
    public static final int STATUS_TAMPERED = 2;
    public static final int STATUS_NO_CASSETTES = 3;

    /** The transcript the module signs; must equal what the terminal computes. */
    public byte[] signedTranscript(byte[] terminalEphemeralPublic, byte[] terminalRandom) {
        return Handshake.transcript(terminalEphemeralPublic, moduleEphemeralPublic, terminalRandom,
                moduleRandom, moduleId.value().getBytes(java.nio.charset.StandardCharsets.UTF_8),
                keyEpoch);
    }

    public byte[] encode() {
        Canonical.Writer w = new Canonical.Writer();
        w.u16(Protocol.VERSION);
        w.bytes(moduleEphemeralPublic);
        w.bytes(moduleRandom);
        w.str(moduleId.value());
        w.str(pairedTerminalId == null ? "" : pairedTerminalId.value());
        w.u32(keyEpoch);
        w.u64(dispenseSeqHighWater);
        w.bool(serviceMode);
        w.u8(statusCode);
        w.bytes(signature);
        return w.toByteArray();
    }

    public static HelloAck decode(byte[] raw) {
        if (raw.length > Protocol.MAX_FRAME_BYTES) {
            throw new ProtoException("HELLO_ACK too large");
        }
        Canonical.Reader r = new Canonical.Reader(raw);
        int ver = r.u16();
        if (ver != Protocol.VERSION) {
            throw new ProtoException("HELLO_ACK version mismatch");
        }
        byte[] eph = r.bytes();
        byte[] rnd = r.bytes();
        String modId = r.str();
        String termId = r.str();
        int epoch = (int) r.u32();
        long highWater = r.u64();
        boolean service = r.bool();
        int status = r.u8();
        byte[] sig = r.bytes();
        r.expectEnd();
        if (eph.length != 32) {
            throw new ProtoException("HELLO_ACK ephemeral key wrong length");
        }
        if (rnd.length < 16 || rnd.length > 64) {
            throw new ProtoException("HELLO_ACK random wrong length");
        }
        if (sig.length != Ed25519.SIGNATURE_BYTES) {
            throw new ProtoException("HELLO_ACK signature wrong length");
        }
        try {
            return new HelloAck(eph, rnd, new ModuleId(modId),
                    termId.isEmpty() ? null : new TerminalId(termId), epoch, highWater, service,
                    status, sig);
        } catch (IllegalArgumentException e) {
            throw new ProtoException("HELLO_ACK identity malformed", e);
        }
    }

    public boolean verifyModuleSignature(PublicKey modulePublicKey, byte[] termEph, byte[] termRnd) {
        return Ed25519.verify(modulePublicKey, signedTranscript(termEph, termRnd), signature);
    }
}
