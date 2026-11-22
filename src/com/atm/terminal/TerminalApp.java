package com.atm.terminal;

import com.atm.bus.BusDevice;
import com.atm.bus.BusFrame;
import com.atm.bus.PhysicalBus;
import com.atm.crypto.Crypto;
import com.atm.dispenser.CashDispenser;
import com.atm.protocol.Protocol;
import com.atm.protocol.Result;
import com.atm.protocol.ResultCode;
import com.atm.protocol.Tlv;
import com.atm.security.DeviceKeys;
import com.atm.security.Kms;
import com.atm.security.OfflineLog;
import com.atm.security.SecureChannel;
import com.atm.util.SimClock;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 业务终端软件（ATM 上位机）。
 * <p>
 * 它持有与出钞模块相同的派生子密钥（配对成功后获得），但<b>没有任何
 * 主机授权密钥 K_AUTH 的签发能力</b>：在线令牌必须向银行主机申请，离线预算
 * 凭证由主机预先下发。因此即便攻击者整机替换并完全控制本软件，也无法让
 * 出钞模块吐出未授权的现金。
 */
public final class TerminalApp implements BusDevice {

    private final String terminalId;
    private final SimClock clock;
    private final NonVolatileTerminalStore store;
    /** 终端身份主密钥（入网时由 KMS 登记，真实部署存于 TPM）。 */
    private final byte[] terminalIdentityKey;

    private PhysicalBus bus;
    private String dispenserId;
    private byte[] kPair;
    private byte[] kChannel;
    private SecureChannel channel;
    private boolean paired;

    // 配对流程临时状态（内存，不落盘）
    private Kms.PairingPackage pendingPackage;
    private byte[] pendingTerminalNonce;
    private byte[] pendingDispenserChallenge;
    private long pendingSeq;
    private volatile boolean pairingDone;
    private volatile ResultCode pairingFailure;
    /** 配对会话进行中标志：仅在 pairWith 期间为 true，结束即清除。 */
    private volatile boolean pairingSessionActive;

    // 终端侧离线日志（与模块侧互为副本，重连对账用）
    private final OfflineLog offlineLog = new OfflineLog();

    /** 最近一帧模块响应，测试与上层业务读取。 */
    private volatile Result lastResult;
    private long requestCounter;

    public TerminalApp(String terminalId, SimClock clock, byte[] terminalIdentityKey) {
        this.terminalId = terminalId;
        this.clock = clock;
        this.terminalIdentityKey = terminalIdentityKey.clone();
        this.store = new NonVolatileTerminalStore(terminalId);
    }

    public String deviceId() {
        return terminalId;
    }

    public void attach(PhysicalBus physicalBus) {
        this.bus = physicalBus;
        physicalBus.attach(this);
    }

    public boolean isPaired() {
        return paired;
    }

    public Result lastResult() {
        return lastResult;
    }

    public long requestCounter() {
        return requestCounter;
    }

    public OfflineLog offlineLog() {
        return offlineLog;
    }

    // ------------------------------------------------------------------
    // 配对：需要物理上已让模块进入配对模式，并持有 KMS 维修工单包
    // ------------------------------------------------------------------

    public Result pairWith(Kms.PairingPackage pkg) {
        // 维修更换场景：持有新的 KMS 工单即可重新配对（模块侧用单调 pairSeq 把关）
        resetPairingState();
        this.pairingSessionActive = true;
        try {
            return doPairing(pkg);
        } finally {
            this.pairingSessionActive = false;
        }
    }

    private Result doPairing(Kms.PairingPackage pkg) {
        this.pendingPackage = pkg;
        this.dispenserId = pkg.ticket().dispenserId();
        this.pendingSeq = pkg.ticket().pairSeq();

        // KDK 信封用终端身份密钥密封，只有工单指定的终端能打开；取出后立即派生各用途密钥
        byte[] kdk;
        try {
            kdk = openEnvelopeLocal(pkg);
        } catch (Crypto.AuthFailureException e) {
            return Result.reject(ResultCode.TICKET_INVALID, "envelope rejected: " + e.getMessage());
        }
        DeviceKeys derived = DeviceKeys.provision(kdk);
        this.kPair = derived.kPair();
        this.kChannel = derived.kChannel();
        this.pendingTerminalNonce = Tlv.longBytes(pkg.ticket().nonce());

        Map<Integer, byte[]> begin = Tlv.builder();
        begin.put(Protocol.T_CMD, Tlv.intBytes(Protocol.PAIR_BEGIN));
        begin.put(Protocol.T_TERMINAL_ID, Tlv.utf8(terminalId));
        begin.put(Protocol.T_DISPENSER_ID, Tlv.utf8(dispenserId));
        begin.put(Protocol.T_PAIR_SEQ, Tlv.longBytes(pendingSeq));
        begin.put(Protocol.T_EXPIRY, Tlv.longBytes(pkg.ticket().expiryEpochSec()));
        begin.put(Protocol.T_TICKET, pkg.sealedTicket());
        this.pendingDispenserChallenge = null;
        this.pairingDone = false;
        this.pairingFailure = null;
        sendPair(Tlv.encode(begin));

        await(() -> pendingDispenserChallenge != null || pairingFailure != null);
        if (pairingFailure != null) {
            return Result.reject(pairingFailure, "pairing rejected at challenge stage");
        }
        if (pendingDispenserChallenge == null) {
            return Result.reject(ResultCode.TICKET_INVALID, "no challenge (module not in pairing mode?)");
        }

        // 确认帧：证明终端确实持有 K_CHANNEL（由 KDK 正确派生）
        Map<Integer, byte[]> confirm = Tlv.builder();
        confirm.put(Protocol.T_CMD, Tlv.intBytes(Protocol.PAIR_CONFIRM));
        confirm.put(Protocol.T_TERMINAL_ID, Tlv.utf8(terminalId));
        confirm.put(Protocol.T_PAIR_SEQ, Tlv.longBytes(pendingSeq));
        confirm.put(Protocol.T_CONFIRM_MAC, computeConfirmMac());
        sendPair(Tlv.encode(confirm));

        await(() -> pairingDone || pairingFailure != null);
        if (pairingFailure != null) {
            return Result.reject(pairingFailure, "pairing rejected at confirm stage");
        }
        if (!paired) {
            return Result.reject(ResultCode.AUTH_FAILED, "pairing not confirmed");
        }
        return Result.ok("paired seq=" + pendingSeq);
    }

    private byte[] openEnvelopeLocal(Kms.PairingPackage pkg) {
        return Crypto.aesGcmOpen(terminalIdentityKey, pkg.ticket().aad(), pkg.kdkEnvelope());
    }

    private byte[] computeConfirmMac() {
        ByteArrayOutputStream c = new ByteArrayOutputStream();
        CashDispenser.writeString(c, dispenserId);
        CashDispenser.writeLong(c, pendingSeq);
        c.write(pendingTerminalNonce, 0, pendingTerminalNonce.length);
        c.write(pendingDispenserChallenge, 0, pendingDispenserChallenge.length);
        return Crypto.hmacSha256(kChannel, c.toByteArray());
    }

    private void sendPair(byte[] plain) {
        byte[] sealed = Crypto.aesGcmSeal(kPair,
                BusFrame.buildAad(Protocol.TYPE_PAIR, terminalId, 0), plain);
        bus.send(this, new BusFrame(Protocol.TYPE_PAIR, terminalId, 0, sealed));
    }

    // ------------------------------------------------------------------
    // 业务 API
    // ------------------------------------------------------------------

    /** 在线出钞：令牌由银行主机签发，终端仅透传。 */
    public Result dispenseOnline(String txnId, long amountMinor, byte[] sealedAuthToken) {
        Map<Integer, byte[]> cmd = Tlv.builder();
        cmd.put(Protocol.T_CMD, Tlv.intBytes(Protocol.CMD_DISPENSE));
        cmd.put(Protocol.T_TXN_ID, Tlv.utf8(txnId));
        cmd.put(Protocol.T_AMOUNT, Tlv.longBytes(amountMinor));
        cmd.put(Protocol.T_TOKEN_KIND, new byte[] {Protocol.TOKEN_KIND_ONLINE});
        cmd.put(Protocol.T_AUTH_TOKEN, sealedAuthToken);
        return sendSecureAndWait(Tlv.encode(cmd));
    }

    /** 离线出钞：使用主机预签的预算凭证，模块本地记账。 */
    public Result dispenseOffline(String txnId, long amountMinor, byte[] sealedBudgetToken) {
        Map<Integer, byte[]> cmd = Tlv.builder();
        cmd.put(Protocol.T_CMD, Tlv.intBytes(Protocol.CMD_DISPENSE));
        cmd.put(Protocol.T_TXN_ID, Tlv.utf8(txnId));
        cmd.put(Protocol.T_AMOUNT, Tlv.longBytes(amountMinor));
        cmd.put(Protocol.T_TOKEN_KIND, new byte[] {Protocol.TOKEN_KIND_OFFLINE_BUDGET});
        cmd.put(Protocol.T_AUTH_TOKEN, sealedBudgetToken);
        Result r = sendSecureAndWait(Tlv.encode(cmd));
        if (r.success()) {
            offlineLog.append(offlineLog.size(), txnId, amountMinor, clock.now());
            store.persistOfflineLog(offlineLog.entries());
        }
        return r;
    }

    public Result queryStatus() {
        Map<Integer, byte[]> cmd = Tlv.builder();
        cmd.put(Protocol.T_CMD, Tlv.intBytes(Protocol.CMD_QUERY_STATUS));
        return sendSecureAndWait(Tlv.encode(cmd));
    }

    public Result heartbeat() {
        Map<Integer, byte[]> cmd = Tlv.builder();
        cmd.put(Protocol.T_CMD, Tlv.intBytes(Protocol.CMD_HEARTBEAT));
        return sendSecureAndWait(Tlv.encode(cmd));
    }

    /** 重连后上送离线日志供主机域核对（模块侧同时校验哈希链）。 */
    public Result uploadOfflineLog() {
        List<OfflineLog.Entry> entries = offlineLog.entries();
        Map<Integer, byte[]> cmd = Tlv.builder();
        cmd.put(Protocol.T_CMD, Tlv.intBytes(Protocol.CMD_UPLOAD_OFFLINE_LOG));
        cmd.put(Protocol.T_LOG_COUNT, Tlv.intBytes(entries.size()));
        cmd.put(Protocol.T_LOG_ENTRY, CashDispenser.serializeLog(entries));
        return sendSecureAndWait(Tlv.encode(cmd));
    }

    /**
     * 测试支撑：通过当前合法安全通道发送任意已构造的命令 TLV。
     * 用于模拟“业务软件已被攻击者完全控制、可以发任意协议消息，
     * 但仍然拿不到主机授权密钥”的威胁场景。
     */
    public Result sendRawCommand(byte[] commandTlv) {
        return sendSecureAndWait(commandTlv);
    }

    private Result sendSecureAndWait(byte[] plain) {
        if (!paired) {
            return Result.reject(ResultCode.NOT_PAIRED);
        }
        byte[] sealed = channel.seal(Protocol.TYPE_SECURE, terminalId, plain);
        long counter = channel.sendCounter() - 1;
        requestCounter++;
        lastResult = null;
        bus.send(this, new BusFrame(Protocol.TYPE_SECURE, terminalId, counter, sealed));
        waitForResponse(200);
        return lastResult != null ? lastResult
                : Result.reject(ResultCode.AUTH_FAILED, "no response");
    }

    // ------------------------------------------------------------------
    // 入帧处理
    // ------------------------------------------------------------------

    @Override
    public void onFrame(BusFrame frame, PhysicalBus sourceBus) {
        try {
            // 只有“正在进行配对会话”的终端才处理 TYPE_PAIR 帧；
            // 已配对或空闲终端对总线上的配对流量保持静默，避免误解析他人会话
            if (frame.type == Protocol.TYPE_PAIR && pairingSessionActive) {
                handlePairingResponse(frame);
            } else if (frame.type == Protocol.TYPE_SECURE && paired) {
                handleSecureResponse(frame);
            }
        } catch (Crypto.AuthFailureException | SecureChannel.ReplayException
                 | IllegalArgumentException ignored) {
            // 广播总线上存在发给其他终端/其他密钥域的帧：解密失败、重放、
            // 字段不匹配都属于“不是给我的帧”，静默丢弃，不影响总线与自身状态
        }
    }

    private void handlePairingResponse(BusFrame frame) {
        byte[] plain;
        try {
            plain = Crypto.aesGcmOpen(kPair, frame.aad(), frame.sealedPayload);
        } catch (Crypto.AuthFailureException e) {
            // 最后一条 PAIR_RESULT 已用 K_CHANNEL 密封，属正常路径，单独尝试
            if (kChannel == null) {
                pairingFailure = ResultCode.AUTH_FAILED;
                return;
            }
            try {
                plain = Crypto.aesGcmOpen(kChannel, frame.aad(), frame.sealedPayload);
            } catch (Crypto.AuthFailureException e2) {
                pairingFailure = ResultCode.AUTH_FAILED;
                return;
            }
        }
        Map<Integer, byte[]> f = Tlv.decode(plain);
        // 总线广播：只接受发给本终端的配对响应（多终端共线场景）
        byte[] target = f.get(Protocol.T_TARGET);
        if (target != null && !Tlv.asUtf8(target).equals(terminalId)) {
            return;
        }
        short sub = (short) Tlv.asInt(f.get(Protocol.T_CMD));
        int status = Tlv.asInt(f.get(Protocol.T_STATUS));
        if (sub != Protocol.PAIR_RESULT || status != ResultCode.OK.code()) {
            pairingFailure = ResultCode.byCode(status);
            lastResult = Result.reject(pairingFailure);
            return;
        }
        if (f.containsKey(Protocol.T_NONCE_DISPENSER)) {
            // 挑战响应
            this.pendingDispenserChallenge = f.get(Protocol.T_NONCE_DISPENSER);
            return;
        }
        if (f.containsKey(Protocol.T_CONFIRM_MAC)) {
            // 配对完成帧：验证模块的 MAC，确认双向身份
            byte[] expected = computeConfirmMac();
            if (!Crypto.constantTimeEquals(expected, f.get(Protocol.T_CONFIRM_MAC))) {
                pairingFailure = ResultCode.AUTH_FAILED;
                return;
            }
            this.channel = new SecureChannel(kChannel, 0);
            this.paired = true;
            this.pairingDone = true;
            store.savePaired(dispenserId, kChannel);
            lastResult = Result.ok();
        }
    }

    private void handleSecureResponse(BusFrame frame) {
        byte[] plain = channel.open(frame);
        Map<Integer, byte[]> f = Tlv.decode(plain);
        // 物理总线是广播介质：只接受发给本终端的响应
        byte[] target = f.get(Protocol.T_TARGET);
        if (target != null && !Tlv.asUtf8(target).equals(terminalId)) {
            return;
        }
        int status = Tlv.asInt(f.get(Protocol.T_RESULT_CODE));
        String detail = f.containsKey(Protocol.T_DETAIL) ? Tlv.asUtf8(f.get(Protocol.T_DETAIL)) : null;
        this.lastResult = new Result(ResultCode.byCode(status), detail);
    }

    /** 测试辅助：模拟重启，内存态清空，配对需从存储恢复或重新配对。 */
    public void reboot() {
        resetPairingState();
    }

    private void resetPairingState() {
        paired = false;
        pairingDone = false;
        pairingFailure = null;
        channel = null;
        kChannel = null;
        kPair = null;
        pendingPackage = null;
        pendingDispenserChallenge = null;
        pendingTerminalNonce = null;
        lastResult = null;
    }

    public void restoreAfterReboot(String dispenserId, byte[] kChannel) {
        this.dispenserId = dispenserId;
        this.kChannel = kChannel.clone();
        this.channel = new SecureChannel(kChannel, 0);
        this.paired = true;
    }

    private void waitForResponse(int ignored) {
        await(() -> lastResult != null);
    }

    /** 同步总线模型下的有界等待：正常路径条件在 send() 调用栈内即已满足。 */
    private void await(java.util.function.BooleanSupplier condition) {
        long deadline = System.nanoTime() + 100_000_000L;
        while (System.nanoTime() < deadline && !condition.getAsBoolean()) {
            Thread.onSpinWait();
        }
    }

    public List<OfflineLog.Entry> storedOfflineLog() {
        return new ArrayList<>(offlineLog.entries());
    }
}
