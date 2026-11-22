package com.bank.atmsecure.wire;

import com.bank.atmsecure.crypto.Canonical;
import com.bank.atmsecure.crypto.CryptoException;
import com.bank.atmsecure.crypto.Ed25519;
import com.bank.atmsecure.crypto.Hex;
import com.bank.atmsecure.crypto.Kdf;
import com.bank.atmsecure.crypto.X25519;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * Terminal side of the link handshake: ephemeral X25519 + transcript-bound key confirmation.
 *
 * <pre>
 *   Terminal                                        Dispenser
 *   HELLO  { eph_pub_T, term_random }        ->
 *                                            <-      HELLO_ACK { eph_pub_D, module_random,
 *                                                         sig_D(transcript) }
 *   [ verify sig_D with module cert key ]
 *   both derive K = HKDF(X25519(eph,eph), transcript)
 * </pre>
 *
 * <p>Key points:
 * <ul>
 *   <li>The dispenser proves possession of its certified key on the <em>first</em> flight, which
 *       costs the weak MCU one signature — acceptable because it happens once per session.</li>
 *   <li>The terminal's key confirmation is implicit: its first AEAD frame authenticates, because
 *       only a party holding the ECDH result can produce a valid tag. That saves the dispenser a
 *       verify on the other side of the handshake.</li>
 *   <li>Both ephemeral keys are fresh per session, so a captured handshake cannot be replayed and no
 *       long-term link secret exists to steal from either box.</li>
 * </ul>
 *
 * <p>What the handshake deliberately does <b>not</b> do: authenticate the terminal PC as a trusted
 * party. The terminal may be replaced; the money-moving permission is the host signature inside the
 * dispense message, verified independently by the module.
 */
public final class Handshake {
    public static final String TRANSCRIPT_DOMAIN = "link-session-transcript-v1";

    private Handshake() {
    }

    public static byte[] transcript(byte[] termEphPub, byte[] moduleEphPub, byte[] termRandom,
            byte[] moduleRandom, byte[] moduleIdUtf8, int keyEpoch) {
        Canonical.Writer w = Canonical.domain(TRANSCRIPT_DOMAIN);
        w.bytes(termEphPub);
        w.bytes(moduleEphPub);
        w.bytes(termRandom);
        w.bytes(moduleRandom);
        w.bytes(moduleIdUtf8);
        w.u32(keyEpoch);
        return w.toByteArray();
    }

    public static byte[] deriveSessionKey(KeyPair myEphemeral, PublicKey theirEphemeral,
            byte[] transcript) {
        byte[] shared = X25519.agree(myEphemeral.getPrivate(), theirEphemeral);
        // Transcript goes in as salt: the key is bound to this exact handshake, not just the DH value.
        return Kdf.hkdf(shared, transcript, "link-session-key", 32);
    }

    /**
     * Channel binding value signed into every host authorisation. It binds the authorisation to the
     * cryptographic session it was minted for, so an authorisation captured on one session cannot be
     * presented on another even before the nonce is considered.
     */
    public static byte[] channelBinding(byte[] sessionKey) {
        return Kdf.hkdf(sessionKey, null, "authorization-channel-binding", 32);
    }

    public static long sessionIdLong(byte[] sessionKey) {
        byte[] h = Kdf.sha256(Canonical.domain("link-session-id").bytes(sessionKey).toByteArray());
        long id = 0;
        for (int i = 0; i < 8; i++) {
            id = (id << 8) | (h[i] & 0xffL);
        }
        return id;
    }

    public static byte[] fingerprint(byte[] channelBinding) {
        return Arrays.copyOf(channelBinding, 8);
    }

    public static String describe(byte[] sessionKey) {
        return "session[" + Hex.encode(fingerprint(channelBinding(sessionKey))) + "]";
    }
}
