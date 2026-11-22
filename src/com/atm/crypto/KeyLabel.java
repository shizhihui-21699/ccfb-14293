package com.atm.crypto;

import java.nio.charset.StandardCharsets;

/**
 * 密钥派生标签。每台设备一个 KDK，按用途域隔离派生密钥，
 * 一个用途的密钥泄露不会影响其他用途。
 */
public final class KeyLabel {

    /** 配对协议专用：加密 KMS 配对票据与密钥注入信封。 */
    public static final byte[] PAIR = "ATM/KEY/PAIR/V1".getBytes(StandardCharsets.UTF_8);

    /** 总线安全通道：终端↔出钞模块之间所有业务帧的 GCM 密钥。 */
    public static final byte[] CHANNEL = "ATM/KEY/CHANNEL/V1".getBytes(StandardCharsets.UTF_8);

    /** 主机授权：银行主机签发在线/离线授权令牌，出钞模块本地验证。 */
    public static final byte[] AUTH = "ATM/KEY/AUTH/V1".getBytes(StandardCharsets.UTF_8);

    private KeyLabel() {
    }
}
