package com.atm.dispenser;

import com.atm.bus.BusDevice;
import com.atm.bus.BusFrame;
import com.atm.bus.PhysicalBus;
import com.atm.crypto.Crypto;
import com.atm.hardware.HardwareSimulator;
import com.atm.protocol.Protocol;
import com.atm.protocol.Result;
import com.atm.protocol.ResultCode;
import com.atm.protocol.Tlv;
import com.atm.security.AuthToken;
import com.atm.security.DeviceKeys;
import com.atm.security.NonVolatileStore;
import com.atm.security.OfflineLog;
import com.atm.security.PairingTicket;
import com.atm.security.SecureChannel;
import com.atm.util.SimClock;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 出钞模块固件（弱算力设备侧的信任根）。
 * <p>
 * 安全状态机：
 * <ul>
 *   <li>未配对：只接受物理配对模式下的配对消息，任何业务帧静默丢弃；</li>
 *   <li>已配对：只接受 K_CHANNEL 认证通过、计数器新鲜、且业务授权齐全的命令；</li>
 *   <li>认证失败的帧不推进任何安全状态（计数器/缓存/额度均不变）。</li>
 * </ul>
 * 配对模式只能由 {@link #enterPairingMode} 进入——它模拟机身内部的物理开关
 * 与双人维修授权，总线消息没有任何办法调用它。
 */
public final class CashDispenser implements BusDevice {

    private static final long PAIR_MODE_TTL_SECONDS = 300;
    private static final int TXN_CACHE_LIMIT = 256;

    private static final String N_PAIR_SEQ = "pairSeq";
    private static final String N_PAIRED_TERMINAL = "pairedTerminal";
    private static final String N_SEND_CTR = "sendCtr";
    private static final String N_RCV_CTR = "rcvCtr";
    private static final String N_OFFLINE_INDEX = "offlineIndex";
    private static final String N_OFFLINE_SPENT = "offlineSpent";
    private static final String N_OFFLINE_LOG = "offlineLog";
    private static final String N_TXN_CACHE = "txnCache";

    private final String dispenserId;
    private final DeviceKeys keys;
    private final NonVolatileStore nvm;
    private final HardwareSimulator hardware;
    private final SimClock clock;

    private PhysicalBus bus;
    private SecureChannel channel;
    private String pairedTerminal;
    private long pairSeq;

    // 物理配对模式（volatile：断电自动退出，必须现场重新操作）
    private boolean pairingMode;
    private long pairingModeSince = -1;

    // 配对过程中的临时挑战值
    private byte[] pendingTerminalNonce;
    private byte[] dispenserChallenge;

    private final OfflineLog offlineLog = new OfflineLog();
    private long offlineSpent;

    // txnId 去重缓存（持久化，重启后仍能识别重放）
    private final LinkedHashMap<Long, Byte> txnCache = new LinkedHashMap<>() {
        @Override
        protected boolean removeEldestEntry(Map.Entry<Long, Byte> eldest) {
            return size() > TXN_CACHE_LIMIT;
        }
    };

    /** 安全事件记录：测试据此断言攻击被拦截。 */
    public record SecurityEvent(long time, ResultCode code, String detail) {
    }

    private final List<SecurityEvent> events = new ArrayList<>();

    public CashDispenser(String dispenserId,
                         DeviceKeys keys,
                         NonVolatileStore nvm,
                         HardwareSimulator hardware,
                         SimClock clock) {
        this.dispenserId = dispenserId;
        this.keys = keys;
        this.nvm = nvm;
        this.hardware = hardware;
        this.clock = clock;
        boot();
    }

    public String deviceId() {
        return dispenserId;
    }

    public void attach(PhysicalBus physicalBus) {
        this.bus = physicalBus;
        physicalBus.attach(this);
    }

    // ------------------------------------------------------------------
    // 启动 / 持久化
    // ------------------------------------------------------------------

    private void boot() {
        this.pairSeq = nvm.getLong(N_PAIR_SEQ, 0);
        this.pairedTerminal = nvm.getString(N_PAIRED_TERMINAL);
        this.offlineSpent = nvm.getLong(N_OFFLINE_SPENT, 0);
        restoreTxnCache();
        restoreOfflineLog();
        if (pairedTerminal != null) {
            this.channel = new SecureChannel(keys.kChannel(), nvm.getLong(N_SEND_CTR, 0));
            // 接收窗口以持久化的计数器为下界重建
            long rcv = nvm.getLong(N_RCV_CTR, -1);
            if (rcv >= 0) {
                channel.resync(rcv);
            }
        }
    }

    private void persistCounters() {
        nvm.putLong(N_SEND_CTR, channel.sendCounter());
        nvm.putLong(N_RCV_CTR, channel.receiveCounter());
    }

    private void restoreTxnCache() {
        byte[] raw = nvm.getBytes(N_TXN_CACHE);
        if (raw == null) {
            return;
        }
        try {
            ByteArrayInputStream in = new ByteArrayInputStream(raw);
            int count = readInt(in);
            for (int i = 0; i < count; i++) {
                long h = readLong(in);
                byte code = (byte) in.read();
                txnCache.put(h, code);
            }
        } catch (Exception e) {
            throw new IllegalStateException("txn cache corrupt", e);
        }
    }

    private void persistTxnCache() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeInt(out, txnCache.size());
        for (Map.Entry<Long, Byte> e : txnCache.entrySet()) {
            writeLong(out, e.getKey());
            out.write(e.getValue() & 0xFF);
        }
        nvm.putBytes(N_TXN_CACHE, out.toByteArray());
    }

    private void restoreOfflineLog() {
        byte[] raw = nvm.getBytes(N_OFFLINE_LOG);
        if (raw == null) {
            return;
        }
        try {
            ByteArrayInputStream in = new ByteArrayInputStream(raw);
            int count = readInt(in);
            for (int i = 0; i < count; i++) {
                long idx = readLong(in);
                String txnId = readString(in);
                long amount = readLong(in);
                long ts = readLong(in);
                byte[] storedPrev = readBytes(in);
                byte[] storedEntryHash = readBytes(in);
                // 用读出的字段重算哈希，与持久化的原始哈希逐字节比对：
                // 任何字段（含 txnId/金额）被物理改写都会导致不匹配
                Map<Integer, byte[]> body = Tlv.builder();
                body.put(Protocol.T_OFFLINE_INDEX, Tlv.longBytes(idx));
                body.put(Protocol.T_TXN_ID, Tlv.utf8(txnId));
                body.put(Protocol.T_AMOUNT, Tlv.longBytes(amount));
                body.put(Protocol.T_EXPIRY, Tlv.longBytes(ts));
                body.put(Protocol.T_DETAIL, storedPrev);
                byte[] recomputed = Crypto.sha256(Tlv.encode(body));
                if (!Crypto.constantTimeEquals(recomputed, storedEntryHash)) {
                    throw new IllegalStateException("stored entry hash mismatch at index " + idx);
                }
                offlineLog.append(idx, txnId, amount, ts);
                // append 重建的 prevHash 也必须与存储一致（检测断链/重排）
                OfflineLog.Entry restored = offlineLog.get(idx);
                if (!Crypto.constantTimeEquals(restored.prevHash(), storedPrev)) {
                    throw new IllegalStateException("prev-hash link broken at index " + idx);
                }
            }
            if (offlineLog.size() != nvm.getLong(N_OFFLINE_INDEX, -1)) {
                throw new IllegalStateException("offline index/log mismatch");
            }
            // 启动自检：重建后的链必须通过独立完整性校验
            Result chainCheck = OfflineLog.verify(offlineLog.entries());
            if (!chainCheck.success()) {
                throw new IllegalStateException("offline log integrity check failed: "
                        + chainCheck.code() + " " + chainCheck.detail());
            }
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("offline log corrupt: " + e.getMessage(), e);
        }
    }

    private void persistOfflineLog() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        List<OfflineLog.Entry> all = offlineLog.entries();
        writeInt(out, all.size());
        for (OfflineLog.Entry e : all) {
            writeLong(out, e.index());
            writeString(out, e.txnId());
            writeLong(out, e.amountMinor());
            writeLong(out, e.timestampSec());
            writeBytes(out, e.prevHash());
            writeBytes(out, e.entryHash());
        }
        nvm.putBytes(N_OFFLINE_LOG, out.toByteArray());
        nvm.putLong(N_OFFLINE_INDEX, offlineLog.size());
        nvm.putLong(N_OFFLINE_SPENT, offlineSpent);
    }

    // ------------------------------------------------------------------
    // 物理配对模式（唯一入口，不接受任何远程触发）
    // ------------------------------------------------------------------

    /** 模拟维修人员拨动机身内配对开关（双人授权 + 现场操作）。 */
    public void enterPairingMode() {
        this.pairingMode = true;
        this.pairingModeSince = clock.now();
    }

    public void exitPairingMode() {
        this.pairingMode = false;
        this.pairingModeSince = -1;
        this.pendingTerminalNonce = null;
        this.dispenserChallenge = null;
    }

    public boolean isPairingMode() {
        if (pairingMode && clock.now() - pairingModeSince > PAIR_MODE_TTL_SECONDS) {
            exitPairingMode();
        }
        return pairingMode;
    }

    public boolean isPaired() {
        return pairedTerminal != null;
    }

    public List<SecurityEvent> securityEvents() {
        return new ArrayList<>(events);
    }

    private void event(ResultCode code, String detail) {
        events.add(new SecurityEvent(clock.now(), code, detail));
    }

    // ------------------------------------------------------------------
    // 总线入口
    // ------------------------------------------------------------------

    @Override
    public void onFrame(BusFrame frame, PhysicalBus sourceBus) {
        try {
            if (frame.type == Protocol.TYPE_PAIR) {
                handlePairing(frame);
            } else if (frame.type == Protocol.TYPE_SECURE) {
                handleSecure(frame);
            } else if (frame.type == Protocol.TYPE_RESYNC) {
                handleResync(frame);
            }
        } catch (Crypto.AuthFailureException e) {
            event(ResultCode.AUTH_FAILED, e.getMessage());
        } catch (SecureChannel.ReplayException e) {
            event(ResultCode.REPLAY_DETECTED, e.getMessage());
        } catch (Exception e) {
            event(ResultCode.AUTH_FAILED, "malformed frame: " + e.getClass().getSimpleName());
        }
    }

    // ------------------------------------------------------------------
    // 配对协议
    // ------------------------------------------------------------------

    private void handlePairing(BusFrame frame) {
        if (!isPairingMode()) {
            // 未进入物理配对模式：任何配对消息一律拒绝，且不回传敏感信息
            event(ResultCode.PAIR_MODE_REQUIRED, "pairing message while not in pairing mode");
            return;
        }
        // 配对消息只能由终端发起；模块自身 ID 的帧（含异常同 ID 实例）不处理
        if (frame.sourceId.equals(dispenserId)) {
            event(ResultCode.AUTH_FAILED, "pairing frame from dispenser-named source ignored");
            return;
        }
        byte[] plain = Crypto.aesGcmOpen(keys.kPair(), frame.aad(), frame.sealedPayload);
        Map<Integer, byte[]> f = Tlv.decode(plain);
        short sub = (short) Tlv.asInt(f.get(Protocol.T_CMD));

        if (sub == Protocol.PAIR_BEGIN) {
            String terminalId = Tlv.asUtf8(f.get(Protocol.T_TERMINAL_ID));
            long claimedSeq = Tlv.asLong(f.get(Protocol.T_PAIR_SEQ));
            long claimedExpiry = Tlv.asLong(f.get(Protocol.T_EXPIRY));
            byte[] sealedTicket = f.get(Protocol.T_TICKET);

            if (claimedSeq <= pairSeq) {
                event(ResultCode.PAIR_SEQ_STALE, "seq=" + claimedSeq + " stored=" + pairSeq);
                sendPairControl(Protocol.PAIR_RESULT, Result.reject(ResultCode.PAIR_SEQ_STALE), terminalId);
                return;
            }
            PairingTicket ticket;
            try {
                ticket = PairingTicket.open(keys.kPair(), dispenserId, terminalId,
                        claimedSeq, claimedExpiry, sealedTicket, clock.now());
            } catch (Crypto.AuthFailureException e) {
                event(ResultCode.TICKET_INVALID, e.getMessage());
                sendPairControl(Protocol.PAIR_RESULT, Result.reject(ResultCode.TICKET_INVALID), terminalId);
                return;
            }
            this.pendingTerminalNonce = Tlv.longBytes(ticket.nonce());
            this.dispenserChallenge = Crypto.randomBytes(16);

            Map<Integer, byte[]> ch = Tlv.builder();
            ch.put(Protocol.T_CMD, Tlv.intBytes(Protocol.PAIR_RESULT));
            ch.put(Protocol.T_TARGET, Tlv.utf8(terminalId));
            ch.put(Protocol.T_STATUS, Tlv.intBytes(ResultCode.OK.code()));
            ch.put(Protocol.T_NONCE_TERMINAL, pendingTerminalNonce);
            ch.put(Protocol.T_NONCE_DISPENSER, dispenserChallenge);
            ch.put(Protocol.T_PAIR_SEQ, Tlv.longBytes(claimedSeq));
            sendPairFrame(Protocol.PAIR_RESULT, Tlv.encode(ch), keys.kPair());
            return;
        }

        if (sub == Protocol.PAIR_CONFIRM) {
            if (dispenserChallenge == null || pendingTerminalNonce == null) {
                event(ResultCode.TICKET_INVALID, "confirm without begin");
                return;
            }
            long claimedSeq = Tlv.asLong(f.get(Protocol.T_PAIR_SEQ));
            String confirmTerminal = Tlv.asUtf8(f.get(Protocol.T_TERMINAL_ID));
            byte[] theirMac = f.get(Protocol.T_CONFIRM_MAC);
            byte[] expectMac = confirmationMac(claimedSeq);
            if (!Crypto.constantTimeEquals(expectMac, theirMac)) {
                event(ResultCode.AUTH_FAILED, "bad pairing confirm MAC");
                sendPairControl(Protocol.PAIR_RESULT, Result.reject(ResultCode.AUTH_FAILED), confirmTerminal);
                return;
            }
            // 配对成立：提交持久化状态
            this.pairedTerminal = Tlv.asUtf8(f.get(Protocol.T_TERMINAL_ID));
            this.pairSeq = claimedSeq;
            this.channel = new SecureChannel(keys.kChannel(), 0);
            nvm.putLong(N_PAIR_SEQ, pairSeq);
            nvm.putString(N_PAIRED_TERMINAL, pairedTerminal);
            nvm.putLong(N_SEND_CTR, 0);
            nvm.putLong(N_RCV_CTR, -1);
            persistCounters();

            // 注意：完成帧的 MAC 仍依赖挑战临时值，必须先发送再退出配对模式
            Map<Integer, byte[]> ok = Tlv.builder();
            ok.put(Protocol.T_CMD, Tlv.intBytes(Protocol.PAIR_RESULT));
            ok.put(Protocol.T_TARGET, Tlv.utf8(pairedTerminal));
            ok.put(Protocol.T_STATUS, Tlv.intBytes(ResultCode.OK.code()));
            ok.put(Protocol.T_TERMINAL_ID, Tlv.utf8(pairedTerminal));
            ok.put(Protocol.T_CONFIRM_MAC, confirmationMac(claimedSeq));
            byte[] payload = Tlv.encode(ok);
            byte[] sealed = channel.seal(Protocol.TYPE_PAIR, dispenserId, payload);
            bus.send(this, new BusFrame(Protocol.TYPE_PAIR, dispenserId, 0, sealed));
            exitPairingMode();
            return;
        }

        event(ResultCode.COMMAND_UNKNOWN, "unknown pairing subcommand " + sub);
    }

    private byte[] confirmationMac(long seq) {
        ByteArrayOutputStream c = new ByteArrayOutputStream();
        writeString(c, dispenserId);
        writeLong(c, seq);
        c.write(pendingTerminalNonce, 0, pendingTerminalNonce.length);
        c.write(dispenserChallenge, 0, dispenserChallenge.length);
        return Crypto.hmacSha256(keys.kChannel(), c.toByteArray());
    }

    private void sendPairControl(short sub, Result result, String targetTerminal) {
        Map<Integer, byte[]> ch = Tlv.builder();
        ch.put(Protocol.T_CMD, Tlv.intBytes(sub));
        if (targetTerminal != null) {
            ch.put(Protocol.T_TARGET, Tlv.utf8(targetTerminal));
        }
        ch.put(Protocol.T_STATUS, Tlv.intBytes(result.code().code()));
        if (result.detail() != null) {
            ch.put(Protocol.T_DETAIL, Tlv.utf8(result.detail()));
        }
        sendPairFrame(Protocol.PAIR_RESULT, Tlv.encode(ch), keys.kPair());
    }

    private void sendPairFrame(short sub, byte[] payload, byte[] sealKey) {
        byte[] sealed = Crypto.aesGcmSeal(sealKey,
                BusFrame.buildAad(Protocol.TYPE_PAIR, dispenserId, 0), payload);
        bus.send(this, new BusFrame(Protocol.TYPE_PAIR, dispenserId, 0, sealed));
    }

    // ------------------------------------------------------------------
    // 安全通道业务帧
    // ------------------------------------------------------------------

    private void handleSecure(BusFrame frame) {
        if (!isPaired()) {
            // 未配对模块对业务帧保持静默，不泄露协议状态
            event(ResultCode.NOT_PAIRED, "secure frame on unpaired module");
            return;
        }
        // 总线是广播介质且可能存在同 ID 的异常实例：只接受配对终端来源的帧。
        // 模块自身（或伪装成模块 ID 的设备）发来的 TYPE_SECURE 帧一律丢弃，
        // 否则两个模块实例会把彼此的响应当命令，形成无限互发。
        if (!pairedTerminal.equals(frame.sourceId)) {
            event(ResultCode.AUTH_FAILED, "secure frame from non-paired source: " + frame.sourceId);
            return;
        }
        byte[] plain = channel.open(frame); // 认证或重放失败：抛异常，状态不变
        Map<Integer, byte[]> f = Tlv.decode(plain);
        short cmd = (short) Tlv.asInt(f.get(Protocol.T_CMD));
        Result result = switch (cmd) {
            case Protocol.CMD_HEARTBEAT -> Result.ok("alive");
            case Protocol.CMD_QUERY_STATUS -> handleStatus();
            case Protocol.CMD_DISPENSE -> handleDispense(f);
            case Protocol.CMD_UPLOAD_OFFLINE_LOG -> handleLogUpload(f);
            default -> Result.reject(ResultCode.COMMAND_UNKNOWN, "cmd=" + cmd);
        };
        persistCounters();
        sendSecureResponse(cmd, result);
    }

    private void handleResync(BusFrame frame) {
        if (!isPaired()) {
            event(ResultCode.NOT_PAIRED, "resync on unpaired module");
            return;
        }
        if (!pairedTerminal.equals(frame.sourceId)) {
            event(ResultCode.AUTH_FAILED, "resync from non-paired source: " + frame.sourceId);
            return;
        }
        // 重同步帧本身仍必须通过 GCM 认证
        byte[] plain = channel.open(frame);
        Map<Integer, byte[]> f = Tlv.decode(plain);
        long proposed = Tlv.asLong(f.get(Protocol.T_NONCE));
        try {
            channel.resync(proposed);
            persistCounters();
            sendSecureResponse(Protocol.CMD_HEARTBEAT, Result.ok("resynced:" + channel.receiveCounter()));
        } catch (SecureChannel.ReplayException e) {
            event(ResultCode.RESYNC_REJECTED, e.getMessage());
        }
    }

    private Result handleStatus() {
        Map<Integer, byte[]> info = Tlv.builder();
        info.put(Protocol.T_CASSETTE_INFO, Tlv.utf8(String.join(",", hardware.cassetteSnapshot())));
        info.put(Protocol.T_CASH_REMAINING, Tlv.longBytes(hardware.cashRemaining()));
        info.put(Protocol.T_OFFLINE_INDEX, Tlv.longBytes(offlineLog.size()));
        info.put(Protocol.T_AMOUNT, Tlv.longBytes(offlineSpent));
        return Result.ok(Tlv.asUtf8(Tlv.encode(info)));
    }

    private Result handleDispense(Map<Integer, byte[]> f) {
        String txnId = Tlv.asUtf8(f.get(Protocol.T_TXN_ID));
        long amount = Tlv.asLong(f.get(Protocol.T_AMOUNT));
        byte[] sealedToken = f.get(Protocol.T_AUTH_TOKEN);
        byte[] kindBytes = f.get(Protocol.T_TOKEN_KIND);
        if (txnId == null || amount <= 0 || sealedToken == null
                || kindBytes == null || kindBytes.length != 1) {
            return Result.reject(ResultCode.AUTH_TOKEN_INVALID, "missing dispense fields");
        }
        byte tokenKind = kindBytes[0];
        long txnHash = txnHash(txnId);
        Byte cached = txnCache.get(txnHash);
        if (cached != null) {
            // 幂等：同一交易绝不第二次出钞
            event(ResultCode.TXN_ALREADY_EXECUTED, "txnId=" + txnId);
            return Result.reject(ResultCode.TXN_ALREADY_EXECUTED,
                    "resultCode=" + cached);
        }

        AuthToken token;
        try {
            // 令牌的 AAD 绑定 txnId：在线令牌绑定真实交易号，离线预算令牌固定为 "*"。
            // 类型标签本身密封在 GCM 帧内，攻击者无法在不破坏 tag 的情况下改写。
            String bindingTxn = tokenKind == Protocol.TOKEN_KIND_OFFLINE_BUDGET ? "*" : txnId;
            token = AuthToken.open(keys.kAuth(), dispenserId, pairedTerminal, bindingTxn, sealedToken);
        } catch (Crypto.AuthFailureException e) {
            event(ResultCode.AUTH_TOKEN_INVALID, e.getMessage());
            return rejectAndCache(txnHash, ResultCode.AUTH_TOKEN_INVALID);
        }
        // 令牌实际类型必须与声明一致，防止把预算令牌伪装成单笔令牌
        boolean declaresOffline = tokenKind == Protocol.TOKEN_KIND_OFFLINE_BUDGET;
        if (declaresOffline != token.offlineBudget()) {
            event(ResultCode.AUTH_TOKEN_INVALID, "token kind mismatch for " + txnId);
            return rejectAndCache(txnHash, ResultCode.AUTH_TOKEN_INVALID);
        }
        if (clock.now() > token.expiryEpochSec()) {
            event(ResultCode.AUTH_TOKEN_EXPIRED, "txnId=" + txnId);
            return rejectAndCache(txnHash, ResultCode.AUTH_TOKEN_EXPIRED);
        }

        Result result;
        if (token.offlineBudget()) {
            result = dispenseOffline(txnId, amount, token);
        } else {
            result = dispenseOnline(txnId, amount, token);
        }
        txnCache.put(txnHash, (byte) result.code().code());
        persistTxnCache();
        return result;
    }

    private Result dispenseOnline(String txnId, long amount, AuthToken token) {
        if (amount != token.amountMinor() || amount > token.perTxnLimitMinor()) {
            event(ResultCode.AMOUNT_MISMATCH,
                    "cmd=" + amount + " token=" + token.amountMinor());
            return Result.reject(ResultCode.AMOUNT_MISMATCH);
        }
        return executeHardware(txnId, amount, false, -1);
    }

    private Result dispenseOffline(String txnId, long amount, AuthToken budget) {
        long now = clock.now();
        if (now < budget.windowStart() || now > budget.windowEnd()) {
            event(ResultCode.AUTH_TOKEN_EXPIRED, "offline window closed for " + txnId);
            return Result.reject(ResultCode.AUTH_TOKEN_EXPIRED, "offline window closed");
        }
        if (amount > budget.perTxnLimitMinor()) {
            event(ResultCode.OFFLINE_QUOTA_EXCEEDED, "per-txn limit for " + txnId);
            return Result.reject(ResultCode.OFFLINE_QUOTA_EXCEEDED);
        }
        if (offlineSpent + amount > budget.amountMinor()) {
            event(ResultCode.OFFLINE_BUDGET_EXHAUSTED,
                    "spent=" + offlineSpent + " need=" + amount + " budget=" + budget.amountMinor());
            return Result.reject(ResultCode.OFFLINE_BUDGET_EXHAUSTED);
        }
        Result r = executeHardware(txnId, amount, true, now);
        if (r.success()) {
            offlineSpent += amount;
            persistOfflineLog();
        }
        return r;
    }

    private Result executeHardware(String txnId, long amount, boolean offline, long ts) {
        long dispensed = hardware.dispense(amount);
        if (dispensed != amount) {
            event(ResultCode.HARDWARE_FAULT, "dispense failed for " + txnId);
            return Result.reject(ResultCode.HARDWARE_FAULT);
        }
        if (offline) {
            offlineLog.append(offlineLog.size(), txnId, amount, ts);
        }
        return Result.ok("dispensed=" + amount);
    }

    private Result rejectAndCache(long txnHash, ResultCode code) {
        txnCache.put(txnHash, (byte) code.code());
        persistTxnCache();
        return Result.reject(code);
    }

    private Result handleLogUpload(Map<Integer, byte[]> f) {
        byte[] raw = f.get(Protocol.T_LOG_ENTRY);
        int claimedCount = Tlv.asInt(f.get(Protocol.T_LOG_COUNT));
        List<OfflineLog.Entry> uploaded = deserializeLog(raw);
        if (uploaded.size() != claimedCount) {
            return Result.reject(ResultCode.LOG_TAMPERED, "count mismatch");
        }
        Result verify = OfflineLog.verify(uploaded);
        if (!verify.success()) {
            event(verify.code(), verify.detail());
            return verify;
        }
        // 终端日志与模块自身日志必须逐条一致
        List<OfflineLog.Entry> mine = offlineLog.entries();
        if (uploaded.size() > mine.size()) {
            return Result.reject(ResultCode.LOG_TAMPERED, "terminal has unknown entries");
        }
        for (int i = 0; i < uploaded.size(); i++) {
            OfflineLog.Entry a = uploaded.get(i);
            OfflineLog.Entry b = mine.get(i);
            if (!Crypto.constantTimeEquals(a.entryHash(), b.entryHash())) {
                event(ResultCode.LOG_TAMPERED, "entry divergence at " + i);
                return Result.reject(ResultCode.LOG_TAMPERED, "divergence at " + i);
            }
        }
        Map<Integer, byte[]> info = Tlv.builder();
        info.put(Protocol.T_OFFLINE_INDEX, Tlv.longBytes(offlineLog.size()));
        info.put(Protocol.T_AMOUNT, Tlv.longBytes(offlineSpent));
        info.put(Protocol.T_DETAIL, offlineLog.headHash());
        return Result.ok(Tlv.asUtf8(Tlv.encode(info)));
    }

    // ------------------------------------------------------------------
    // 响应发送
    // ------------------------------------------------------------------

    private void sendSecureResponse(short cmd, Result result) {
        Map<Integer, byte[]> r = Tlv.builder();
        r.put(Protocol.T_CMD, Tlv.intBytes(cmd));
        r.put(Protocol.T_TARGET, Tlv.utf8(pairedTerminal));
        r.put(Protocol.T_RESULT_CODE, Tlv.intBytes(result.code().code()));
        if (result.detail() != null) {
            r.put(Protocol.T_DETAIL, Tlv.utf8(result.detail()));
        }
        byte[] sealed = channel.seal(Protocol.TYPE_SECURE, dispenserId, Tlv.encode(r));
        bus.send(this, new BusFrame(Protocol.TYPE_SECURE, dispenserId, channel.sendCounter() - 1, sealed));
    }

    // ------------------------------------------------------------------
    // 辅助
    // ------------------------------------------------------------------

    private static long txnHash(String txnId) {
        byte[] h = Crypto.sha256(Tlv.utf8(txnId));
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (h[i] & 0xFFL);
        }
        return v;
    }

    @Override
    public String toString() {
        return "CashDispenser{" + dispenserId + ", paired=" + isPaired() + "}";
    }

    // ---- 原始类型序列化（public：终端侧日志持久化复用同一格式） ----
    public static void writeInt(ByteArrayOutputStream out, int v) {
        out.write((v >>> 24) & 0xFF);
        out.write((v >>> 16) & 0xFF);
        out.write((v >>> 8) & 0xFF);
        out.write(v & 0xFF);
    }

    public static int readInt(ByteArrayInputStream in) {
        return (in.read() << 24) | (in.read() << 16) | (in.read() << 8) | in.read();
    }

    public static void writeLong(ByteArrayOutputStream out, long v) {
        for (int i = 7; i >= 0; i--) {
            out.write((byte) (v >>> (8 * i)));
        }
    }

    public static long readLong(ByteArrayInputStream in) {
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (in.read() & 0xFFL);
        }
        return v;
    }

    public static void writeString(ByteArrayOutputStream out, String s) {
        byte[] b = Tlv.utf8(s);
        writeInt(out, b.length);
        out.write(b, 0, b.length);
    }

    public static String readString(ByteArrayInputStream in) {
        int len = readInt(in);
        try {
            byte[] b = in.readNBytes(len);
            return Tlv.asUtf8(b);
        } catch (java.io.IOException e) {
            throw new IllegalStateException("failed reading string field", e);
        }
    }

    public static void writeBytes(ByteArrayOutputStream out, byte[] b) {
        writeInt(out, b.length);
        out.write(b, 0, b.length);
    }

    public static byte[] readBytes(ByteArrayInputStream in) {
        int len = readInt(in);
        try {
            return in.readNBytes(len);
        } catch (java.io.IOException e) {
            throw new IllegalStateException("failed reading bytes field", e);
        }
    }

    /** 日志序列化：字段 + 前向哈希 + 条目哈希，哈希是篡改检测的锚点。 */
    public static byte[] serializeLog(List<OfflineLog.Entry> log) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeInt(out, log.size());
        for (OfflineLog.Entry e : log) {
            writeLong(out, e.index());
            writeString(out, e.txnId());
            writeLong(out, e.amountMinor());
            writeLong(out, e.timestampSec());
            writeBytes(out, e.prevHash());
            writeBytes(out, e.entryHash());
        }
        return out.toByteArray();
    }

    /**
     * 上传日志的反序列化：保留持久化的原始哈希，链完整性随后由
     * {@link OfflineLog#verify} 独立校验（重算哈希必须与存储哈希一致）。
     */
    public static List<OfflineLog.Entry> deserializeLog(byte[] raw) {
        List<OfflineLog.Entry> rebuilt = new ArrayList<>();
        if (raw == null) {
            return rebuilt;
        }
        ByteArrayInputStream in = new ByteArrayInputStream(raw);
        int count = readInt(in);
        for (int i = 0; i < count; i++) {
            long idx = readLong(in);
            String txnId = readString(in);
            long amount = readLong(in);
            long ts = readLong(in);
            byte[] storedPrev = readBytes(in);
            byte[] storedEntryHash = readBytes(in);
            // 保留持久化的原始哈希：verify 会重算并与之比对，
            // 任何字段篡改都会导致重算哈希 ≠ 存储哈希
            rebuilt.add(new OfflineLog.Entry(idx, txnId, amount, ts, storedPrev, storedEntryHash));
        }
        return rebuilt;
    }
}
