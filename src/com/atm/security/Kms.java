package com.atm.security;

import com.atm.crypto.Crypto;
import com.atm.util.SimClock;

import java.util.HashMap;
import java.util.Map;

/**
 * 模拟银行密钥管理系统（KMS）/ 授权主机域。
 * <p>
 * 现实中对应 HSM 集群：保存每台出钞模块产线注入的 KDK，
 * 负责（1）维修工单触发的配对票据与密钥信封签发；（2）在线交易授权令牌；
 * （3）离线预算凭证。业务终端永远拿不到 KDK 本身，只能拿到 KMS 为某次
 * 维修工单密封好的、与一次性票据绑定的信封。
 */
public final class Kms {

    /** 一台出钞模块的产线记录：KDK 与当前已签发的最大配对序号。 */
    public record DeviceRecord(String dispenserId, byte[] kdk, long lastPairSeq) {
    }

    private final Map<String, DeviceRecord> devices = new HashMap<>();
    /** 入网终端的身份主密钥（真实部署中终端侧副本存于 TPM/安全元件）。 */
    private final Map<String, byte[]> terminalKeys = new HashMap<>();
    private final SimClock clock;
    private long nonceCounter = 1_000_000L;

    public Kms(SimClock clock) {
        this.clock = clock;
    }

    /** 模拟产线注入：登记模块 KDK。 */
    public synchronized DeviceKeys enrollDevice(String dispenserId, byte[] kdk) {
        if (devices.containsKey(dispenserId)) {
            throw new IllegalStateException("device already enrolled: " + dispenserId);
        }
        devices.put(dispenserId, new DeviceRecord(dispenserId, kdk.clone(), 0));
        return DeviceKeys.provision(kdk);
    }

    /**
     * 终端入网：KMS 为该终端生成并登记身份主密钥，返回终端侧副本。
     * 配对工单中的 KDK 信封只能由对应终端的身份密钥打开。
     */
    public synchronized byte[] enrollTerminal(String terminalId) {
        if (terminalKeys.containsKey(terminalId)) {
            throw new IllegalStateException("terminal already enrolled: " + terminalId);
        }
        byte[] key = Crypto.randomBytes(Crypto.AES_KEY_LEN);
        terminalKeys.put(terminalId, key.clone());
        return key;
    }

    public synchronized boolean knowsDevice(String dispenserId) {
        return devices.containsKey(dispenserId);
    }

    private DeviceRecord record(String dispenserId) {
        DeviceRecord r = devices.get(dispenserId);
        if (r == null) {
            throw new IllegalArgumentException("unknown dispenser: " + dispenserId);
        }
        return r;
    }

    /** 维修工单产物：一次性配对票据 + 与票据绑定、定向到指定终端的 KDK 密封信封。 */
    public synchronized PairingPackage issuePairingPackage(String dispenserId,
                                                            String newTerminalId,
                                                            long ticketTtlSeconds) {
        DeviceRecord r = record(dispenserId);
        byte[] terminalKey = terminalKeys.get(newTerminalId);
        if (terminalKey == null) {
            throw new IllegalArgumentException("terminal not enrolled: " + newTerminalId);
        }
        long newSeq = r.lastPairSeq() + 1;
        devices.put(dispenserId, new DeviceRecord(dispenserId, r.kdk(), newSeq));

        DeviceKeys keys = DeviceKeys.provision(r.kdk());
        long now = clock.now();
        PairingTicket ticket = new PairingTicket(
                dispenserId, newTerminalId, newSeq, nextNonce(), now + ticketTtlSeconds);
        byte[] sealedTicket = ticket.seal(keys.kPair());
        // 信封用终端身份密钥密封：只有工单指定的终端能打开；
        // AAD 绑定票据头部，信封与工单密码学绑定、无法挪用
        byte[] envelope = Crypto.aesGcmSeal(terminalKey, ticket.aad(), r.kdk());
        return new PairingPackage(ticket, sealedTicket, envelope);
    }

    /** 在线交易授权：主机确认扣款后签发单笔令牌。 */
    public synchronized byte[] issueOnlineAuthToken(String dispenserId,
                                                     String terminalId,
                                                     String txnId,
                                                     long amountMinor,
                                                     long ttlSeconds) {
        DeviceRecord r = record(dispenserId);
        DeviceKeys keys = DeviceKeys.provision(r.kdk());
        long now = clock.now();
        AuthToken token = new AuthToken(dispenserId, terminalId, txnId, amountMinor,
                amountMinor, now, now + ttlSeconds, 0, 0, nextNonce());
        return token.seal(keys.kAuth());
    }

    /**
     * 离线预算凭证：断网前（或上一次重连时）下发，限制时间窗内的
     * 累计额度与单笔上限。模块本地强制执行，重连后主机按日志核对。
     */
    public synchronized byte[] issueOfflineBudget(String dispenserId,
                                                   String terminalId,
                                                   long totalBudgetMinor,
                                                   long perTxnLimitMinor,
                                                   long windowStart,
                                                   long windowEnd) {
        DeviceRecord r = record(dispenserId);
        DeviceKeys keys = DeviceKeys.provision(r.kdk());
        AuthToken token = new AuthToken(dispenserId, terminalId, "*",
                totalBudgetMinor, perTxnLimitMinor, clock.now(), windowEnd,
                windowStart, windowEnd, nextNonce());
        return token.seal(keys.kAuth());
    }

    private long nextNonce() {
        return nonceCounter++;
    }

    /** 配对工单交付包。信封 AAD 与票据 AAD 相同，二者被密码学绑定。 */
    public record PairingPackage(PairingTicket ticket, byte[] sealedTicket, byte[] kdkEnvelope) {
    }
}
