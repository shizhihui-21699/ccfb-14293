package com.atm.security;

import com.atm.crypto.Crypto;
import com.atm.crypto.KeyLabel;

/**
 * 设备密钥材料。每个出钞模块在生产阶段由银行 KMS 注入唯一 KDK（存于模拟安全存储），
 * 所有用途密钥由 KDK 经 HKDF 域隔离派生，永不在总线上出现。
 */
public final class DeviceKeys {

    private final byte[] kdk;          // 32B 密钥派生主密钥
    private final byte[] kPair;        // 配对协议密钥
    private final byte[] kChannel;     // 总线安全通道密钥
    private final byte[] kAuth;        // 主机授权令牌验证密钥

    private DeviceKeys(byte[] kdk) {
        if (kdk == null || kdk.length != Crypto.AES_KEY_LEN) {
            throw new IllegalArgumentException("KDK must be 32 bytes");
        }
        this.kdk = kdk.clone();
        this.kPair = Crypto.hkdf(kdk, KeyLabel.PAIR, Crypto.AES_KEY_LEN);
        this.kChannel = Crypto.hkdf(kdk, KeyLabel.CHANNEL, Crypto.AES_KEY_LEN);
        this.kAuth = Crypto.hkdf(kdk, KeyLabel.AUTH, Crypto.AES_KEY_LEN);
    }

    /** 工厂注入新 KDK（模拟产线安全注入工位）。 */
    public static DeviceKeys provision(byte[] kdk) {
        return new DeviceKeys(kdk);
    }

    public byte[] kdk() {
        return kdk.clone();
    }

    public byte[] kPair() {
        return kPair.clone();
    }

    public byte[] kChannel() {
        return kChannel.clone();
    }

    public byte[] kAuth() {
        return kAuth.clone();
    }

    /**
     * 密钥注入信封：维修更换场景下，KMS 把目标模块 KDK 的副本用该模块的
     * K_PAIR 密封后交给新终端。信封与一次性配对票据绑定（见 PairingTicket），
     * 终端只在配对流程中临时持有，配对完成后内存副本即清除。
     */
    public static byte[] sealEnvelope(byte[] targetKPair, byte[] kdk, byte[] contextAad) {
        return Crypto.aesGcmSeal(targetKPair, contextAad, kdk);
    }

    public static byte[] openEnvelope(byte[] targetKPair, byte[] sealed, byte[] contextAad) {
        return Crypto.aesGcmOpen(targetKPair, contextAad, sealed);
    }
}
