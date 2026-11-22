package com.bank.atmsecure.auth;

import com.bank.atmsecure.crypto.Canonical;
import com.bank.atmsecure.crypto.CryptoException;
import com.bank.atmsecure.crypto.Ed25519;
import com.bank.atmsecure.model.ModuleId;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Manufacturing certificate binding a module identity to the module's own keypair, signed by the
 * host. Written into the module's one-time-programmable flash at the factory.
 *
 * <p>Because it is OTP, the module can never present a different identity or key later, and a
 * counterfeit module cannot obtain a valid certificate without the host's manufacturing key.
 */
public final class ModuleCertificate {
    public static final String DOMAIN = "module-manufacturing-certificate-v1";

    private final ModuleId moduleId;
    private final byte[] modulePublicKey;
    private final String serial;
    private final long manufacturedAtMillis;
    private final byte[] signature;

    public ModuleCertificate(ModuleId moduleId, byte[] modulePublicKey, String serial,
            long manufacturedAtMillis, byte[] signature) {
        this.moduleId = moduleId;
        this.modulePublicKey = Canonical.copy(modulePublicKey);
        this.serial = serial;
        this.manufacturedAtMillis = manufacturedAtMillis;
        this.signature = Canonical.copy(signature);
    }

    public ModuleId moduleId() {
        return moduleId;
    }

    public byte[] modulePublicKey() {
        return Canonical.copy(modulePublicKey);
    }

    public String serial() {
        return serial;
    }

    public long manufacturedAtMillis() {
        return manufacturedAtMillis;
    }

    public byte[] unsignedBytes() {
        Canonical.Writer w = Canonical.domain(DOMAIN);
        w.str(moduleId.value());
        w.bytes(modulePublicKey);
        w.str(serial);
        w.u64(manufacturedAtMillis);
        return w.toByteArray();
    }

    public static ModuleCertificate issue(PrivateKey manufacturingKey, ModuleId moduleId,
            PublicKey modulePublicKey, String serial, long manufacturedAtMillis) {
        byte[] raw = Ed25519.rawPublic(modulePublicKey);
        ModuleCertificate unsigned =
                new ModuleCertificate(moduleId, raw, serial, manufacturedAtMillis, new byte[0]);
        byte[] sig = Ed25519.sign(manufacturingKey, unsigned.unsignedBytes());
        return new ModuleCertificate(moduleId, raw, serial, manufacturedAtMillis, sig);
    }

    public boolean verify(PublicKey manufacturingKey) {
        return Ed25519.verify(manufacturingKey, unsignedBytes(), signature);
    }

    public PublicKey modulePublicKeyObject() {
        return Ed25519.fromRawPublic(modulePublicKey);
    }

    public byte[] encode() {
        Canonical.Writer w = new Canonical.Writer();
        w.bytes(unsignedBytes());
        w.bytes(signature);
        return w.toByteArray();
    }

    public static ModuleCertificate decode(byte[] encoded) {
        Canonical.Reader r = new Canonical.Reader(encoded);
        byte[] body = r.bytes();
        byte[] sig = r.bytes();
        r.expectEnd();
        Canonical.Reader br = new Canonical.Reader(body);
        // Re-check domain prefix to avoid type confusion between signed structures.
        byte[] magic = br.fixed(4);
        if (magic[0] != 'A' || magic[1] != 'T' || magic[2] != 'M' || magic[3] != '1') {
            throw new CryptoException("bad domain magic");
        }
        if (!DOMAIN.equals(br.str())) {
            throw new CryptoException("wrong certificate domain");
        }
        ModuleId id = new ModuleId(br.str());
        byte[] pub = br.bytes();
        String serial = br.str();
        long t = br.u64();
        br.expectEnd();
        if (pub.length != Ed25519.PUBLIC_KEY_BYTES) {
            throw new CryptoException("module public key wrong length");
        }
        return new ModuleCertificate(id, pub, serial, t, sig);
    }

    @Override
    public String toString() {
        return "ModuleCertificate[" + moduleId + " serial=" + serial + "]";
    }
}
