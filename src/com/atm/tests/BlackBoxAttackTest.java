package com.atm.tests;

import com.atm.bus.BusFrame;
import com.atm.crypto.Crypto;
import com.atm.protocol.Protocol;
import com.atm.protocol.Result;
import com.atm.protocol.ResultCode;
import com.atm.protocol.Tlv;
import com.atm.security.Kms;
import com.atm.security.SecureChannel;

import java.util.List;
import java.util.Map;

/**
 * 黑盒攻击测试套件——直接复现并防御题目描述的真实入侵：
 * 撬开机柜、小电脑挂到出钞模块数据线上发送出钞指令。
 * <p>
 * 每个用例的最终断言都落在 {@code hardware.totalDispensed()}：
 * 只要有任何攻击真的驱动了机械出钞，测试即失败。
 */
public final class BlackBoxAttackTest extends AtmTest {

    public static List<AtmTest> suite() {
        return List.of(
                new BlackBoxAttackTest("基线:合法在线交易正常出钞", () -> new BlackBoxAttackTest().tBaselineLegitDispense()),
                new BlackBoxAttackTest("攻击1:无密钥裸出钞指令(原始漏洞复现)", () -> new BlackBoxAttackTest().tRawDispense()),
                new BlackBoxAttackTest("攻击2:垃圾帧泛洪不污染安全状态", () -> new BlackBoxAttackTest().tGarbageFlood()),
                new BlackBoxAttackTest("攻击3:重放历史出钞帧不二次出钞", () -> new BlackBoxAttackTest().tReplayDispenseFrame()),
                new BlackBoxAttackTest("攻击4:篡改密封载荷被GCM拒绝", () -> new BlackBoxAttackTest().tTamperPayload()),
                new BlackBoxAttackTest("攻击5:篡改帧头(sourceId/计数器)被AAD拒绝", () -> new BlackBoxAttackTest().tTamperHeader()),
                new BlackBoxAttackTest("攻击6:伪造配对消息被拒", () -> new BlackBoxAttackTest().tFakePairing()),
                new BlackBoxAttackTest("攻击7:伪造重同步无法推高计数器", () -> new BlackBoxAttackTest().tFakeResync()),
                new BlackBoxAttackTest("攻击8:攻击者自制令牌无法出钞", () -> new BlackBoxAttackTest().tForgedAuthToken()),
                new BlackBoxAttackTest("攻击9:篡改命令金额与令牌不符被拒", () -> new BlackBoxAttackTest().tAmountMismatch()),
                new BlackBoxAttackTest("攻击10:替换业务电脑整机后无法出钞", () -> new BlackBoxAttackTest().tRoguePcReplacement()),
                new BlackBoxAttackTest("攻击11:MITM拦截篡改后合法通道仍存活", () -> new BlackBoxAttackTest().tMitmTamper()),
                new BlackBoxAttackTest("攻击12:MITM丢弃帧只影响可用性不出钞", () -> new BlackBoxAttackTest().tMitmDrop()),
                new BlackBoxAttackTest("攻击13:同一txnId重复请求幂等不重付", () -> new BlackBoxAttackTest().tDuplicateTxnId()),
                new BlackBoxAttackTest("攻击14:重放配对帧无法触发配对", () -> new BlackBoxAttackTest().tReplayPairingFrame()),
                new BlackBoxAttackTest("攻击15:未配对模块对业务帧保持静默", () -> new BlackBoxAttackTest().tUnpairedSilence()),
                new BlackBoxAttackTest("攻击16:伪造其他模块的令牌跨设备挪用", () -> new BlackBoxAttackTest().tCrossDeviceToken()));
    }

    private final Runnable body;

    private BlackBoxAttackTest() {
        this.overrideName = null;
        this.body = null;
    }
    private final String overrideName;

    private BlackBoxAttackTest(String name, Runnable body) {
        this.overrideName = name;
        this.body = body;
    }

    @Override
    public String name() {
        return overrideName;
    }

    @Override
    public void run() {
        body.run();
    }

    private void tBaselineLegitDispense() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        long before = env.hardware.totalDispensed();
        Result r = env.terminal.dispenseOnline("TXN-1", 1000, env.onlineToken("TXN-1", 1000));
        check(r.success(), "legit dispense accepted: " + r);
        checkEq(env.hardware.totalDispensed(), before + 1000, "exact amount dispensed once");
    }

    private void tRawDispense() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        long cashBefore = env.hardware.totalDispensed();
        // 攻击者直接在数据线上发裸出钞命令，冒充合法终端 sourceId
        env.attacker.rawDispenseCommand(env.bus, env.terminalId, "HEIST-1", 50000);
        checkEq(env.hardware.totalDispensed(), cashBefore, "raw command dispenses nothing");
        check(hasEvent(env, ResultCode.AUTH_FAILED), "auth failure recorded");
        // 攻击之后合法交易依然正常——状态没有被破坏
        Result legit = env.terminal.dispenseOnline("TXN-OK", 500, env.onlineToken("TXN-OK", 500));
        check(legit.success(), "legit channel survives attack: " + legit);
        checkEq(env.hardware.totalDispensed(), cashBefore + 500, "only legit amount dispensed");
    }

    private void tGarbageFlood() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        long cash = env.hardware.totalDispensed();
        long rcvBefore = env.dispenser.securityEvents().size();
        env.attacker.flood(env.bus, env.terminalId, 200);
        checkEq(env.hardware.totalDispensed(), cash, "flood dispenses nothing");
        check(env.dispenser.securityEvents().size() > rcvBefore, "each garbage frame logged as auth failure");
        Result legit = env.terminal.heartbeat();
        check(legit.success(), "channel healthy after flood: " + legit);
    }

    private void tReplayDispenseFrame() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        env.bus.clearSniffer();
        Result r = env.terminal.dispenseOnline("TXN-R", 800, env.onlineToken("TXN-R", 800));
        check(r.success(), "first dispense ok");
        long afterFirst = env.hardware.totalDispensed();
        List<BusFrame> captured = env.bus.sniffedFrames();
        BusFrame dispenseFrame = captured.stream()
                .filter(f -> f.type == Protocol.TYPE_SECURE)
                .findFirst().orElseThrow();
        // 原样重放 N 次
        for (int i = 0; i < 5; i++) {
            env.attacker.replay(env.bus, dispenseFrame);
        }
        checkEq(env.hardware.totalDispensed(), afterFirst, "replays never dispense again");
        check(hasEvent(env, ResultCode.REPLAY_DETECTED), "replay events detected");
    }

    private void tTamperPayload() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        env.bus.clearSniffer();
        env.terminal.dispenseOnline("TXN-T", 700, env.onlineToken("TXN-T", 700));
        long cash = env.hardware.totalDispensed();
        BusFrame target = env.bus.sniffedFrames().get(0);
        // 翻转密文区多个字节（含尝试改金额区域）
        for (int offset : new int[] {15, 20, 30}) {
            env.attacker.tamperAndReplay(env.bus, target, offset);
        }
        checkEq(env.hardware.totalDispensed(), cash, "tampered frames rejected, no extra cash");
        check(hasEvent(env, ResultCode.AUTH_FAILED), "GCM tag failures recorded");
    }

    private void tTamperHeader() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        env.bus.clearSniffer();
        env.terminal.heartbeat();
        BusFrame f = env.bus.sniffedFrames().get(0);
        long cash = env.hardware.totalDispensed();
        // 改 sourceId（冒充别的终端）与改计数器，载荷原样——AAD 失配
        env.attacker.tamperHeaderAndReplay(env.bus, f, "TERM-FAKE", f.counter);
        env.attacker.tamperHeaderAndReplay(env.bus, f, f.sourceId, f.counter + 1);
        checkEq(env.hardware.totalDispensed(), cash, "header tamper rejected");
        check(hasEvent(env, ResultCode.AUTH_FAILED), "AAD mismatch recorded");
    }

    private void tFakePairing() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        // 即便模块恰好处于配对模式，攻击者没有 KMS 票据也配不上
        env.dispenser.enterPairingMode();
        env.attacker.fakePairingBegin(env.bus, env.dispenserId, "EVIL-TERM", 999);
        check(env.terminal.isPaired(), "legit terminal still the paired party");
        check(hasEvent(env, ResultCode.TICKET_INVALID) || hasEvent(env, ResultCode.AUTH_FAILED),
                "fake pairing rejected");
        // 未进入配对模式时更应被拒
        TestEnvironment env2 = new TestEnvironment();
        env2.attacker.fakePairingBegin(env2.bus, env2.dispenserId, "EVIL", 1);
        check(hasEvent(env2, ResultCode.PAIR_MODE_REQUIRED), "pairing gate closed");
    }

    private void tFakeResync() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        long cash = env.hardware.totalDispensed();
        // 没有 K_CHANNEL，resync 帧内容无法通过 GCM
        env.attacker.fakeResync(env.bus, env.terminalId, Long.MAX_VALUE / 2);
        check(hasEvent(env, ResultCode.AUTH_FAILED), "forged resync fails auth");
        Result hb = env.terminal.heartbeat();
        check(hb.success(), "counter state not poisoned: " + hb);
        checkEq(env.hardware.totalDispensed(), cash, "no cash from resync attack");
    }

    private void tForgedAuthToken() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        long cash = env.hardware.totalDispensed();
        // 攻击者控制了业务软件，能发送合法 GCM 帧，但拿不到 K_AUTH，
        // 只能塞一个随机字节当授权令牌
        Map<Integer, byte[]> cmd = Tlv.builder();
        cmd.put(Protocol.T_CMD, Tlv.intBytes(Protocol.CMD_DISPENSE));
        cmd.put(Protocol.T_TXN_ID, Tlv.utf8("FORGED-TOKEN-1"));
        cmd.put(Protocol.T_AMOUNT, Tlv.longBytes(2000));
        cmd.put(Protocol.T_TOKEN_KIND, new byte[] {Protocol.TOKEN_KIND_ONLINE});
        cmd.put(Protocol.T_AUTH_TOKEN, Crypto.randomBytes(60));
        Result r = sendAsTerminal(env, Tlv.encode(cmd));
        check(!r.success() && r.code() == ResultCode.AUTH_TOKEN_INVALID,
                "forged token rejected: " + r);
        checkEq(env.hardware.totalDispensed(), cash, "forged token yields no cash");
    }

    private void tAmountMismatch() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        long cash = env.hardware.totalDispensed();
        // 合法令牌只授权 500，命令却要 5000（攻击者控制 PC 后改金额）
        byte[] token = env.onlineToken("TXN-M", 500);
        Map<Integer, byte[]> cmd = Tlv.builder();
        cmd.put(Protocol.T_CMD, Tlv.intBytes(Protocol.CMD_DISPENSE));
        cmd.put(Protocol.T_TXN_ID, Tlv.utf8("TXN-M"));
        cmd.put(Protocol.T_AMOUNT, Tlv.longBytes(5000));
        cmd.put(Protocol.T_TOKEN_KIND, new byte[] {Protocol.TOKEN_KIND_ONLINE});
        cmd.put(Protocol.T_AUTH_TOKEN, token);
        Result r = sendAsTerminal(env, Tlv.encode(cmd));
        check(!r.success() && r.code() == ResultCode.AMOUNT_MISMATCH, "amount mismatch rejected: " + r);
        checkEq(env.hardware.totalDispensed(), cash, "no over-withdrawal");
    }

    private void tRoguePcReplacement() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        long cash = env.hardware.totalDispensed();
        // 攻击者整机替换：新电脑知道协议格式，却没有 KMS 登记的合法身份
        var rogue = new com.atm.terminal.TerminalApp("ROGUE-PC", env.clock, Crypto.randomBytes(32));
        rogue.attach(env.bus);
        // 未配对直接尝试出钞
        Result unpaired = rogue.dispenseOnline("HEIST-PC", 9000, env.onlineToken("HEIST-PC", 9000));
        check(!unpaired.success(), "rogue PC blocked before reaching dispenser: " + unpaired);
        // 尝试直接注入伪造 GCM 帧
        SecureChannel bogus = new SecureChannel(Crypto.randomBytes(32));
        Map<Integer, byte[]> cmd = Tlv.builder();
        cmd.put(Protocol.T_CMD, Tlv.intBytes(Protocol.CMD_DISPENSE));
        cmd.put(Protocol.T_TXN_ID, Tlv.utf8("HEIST-PC2"));
        cmd.put(Protocol.T_AMOUNT, Tlv.longBytes(9000));
        cmd.put(Protocol.T_TOKEN_KIND, new byte[] {Protocol.TOKEN_KIND_ONLINE});
        cmd.put(Protocol.T_AUTH_TOKEN, env.onlineToken("HEIST-PC2", 9000));
        byte[] sealed = bogus.seal(Protocol.TYPE_SECURE, "ROGUE-PC", Tlv.encode(cmd));
        env.bus.inject(new BusFrame(Protocol.TYPE_SECURE, "ROGUE-PC", 0, sealed));
        checkEq(env.hardware.totalDispensed(), cash, "rogue PC never dispenses");
        check(hasEvent(env, ResultCode.AUTH_FAILED), "wrong channel key rejected");
    }

    private void tMitmTamper() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        long cash = env.hardware.totalDispensed();
        // MITM 对每一帧做字节翻转
        env.bus.setMitm(frame -> {
            byte[] p = frame.sealedPayload.clone();
            int mid = p.length / 2;
            p[mid] = (byte) (p[mid] ^ 0xFF);
            return new BusFrame(frame.type, frame.sourceId, frame.counter, p);
        });
        Result r = env.terminal.dispenseOnline("MITM-1", 600, env.onlineToken("MITM-1", 600));
        check(!r.success(), "MITM-tampered frame cannot be accepted: " + r);
        checkEq(env.hardware.totalDispensed(), cash, "MITM cannot cause dispense");
        env.bus.setMitm(null);
        // 移除 MITM 后通道自动恢复，无需重新配对
        Result recover = env.terminal.dispenseOnline("MITM-2", 600, env.onlineToken("MITM-2", 600));
        check(recover.success(), "channel recovers after MITM removed: " + recover);
        checkEq(env.hardware.totalDispensed(), cash + 600, "legit dispense after recovery");
    }

    private void tMitmDrop() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        long cash = env.hardware.totalDispensed();
        env.bus.setMitm(frame -> null); // 全量丢弃
        Result r = env.terminal.dispenseOnline("DROP-1", 600, env.onlineToken("DROP-1", 600));
        check(!r.success(), "dropped frame yields failure to caller");
        checkEq(env.hardware.totalDispensed(), cash, "dropped commands never execute");
        env.bus.setMitm(null);
        check(env.terminal.heartbeat().success(), "availability restored");
    }

    private void tDuplicateTxnId() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        byte[] token = env.onlineToken("DUP-1", 400);
        Result first = env.terminal.dispenseOnline("DUP-1", 400, token);
        check(first.success(), "first ok");
        long cash = env.hardware.totalDispensed();
        // 攻击者用同一 txnId（以及同一令牌）反复发起
        for (int i = 0; i < 3; i++) {
            Result dup = env.terminal.dispenseOnline("DUP-1", 400, token);
            check(!dup.success() && dup.code() == ResultCode.TXN_ALREADY_EXECUTED,
                    "duplicate rejected idempotently: " + dup);
        }
        checkEq(env.hardware.totalDispensed(), cash, "paid exactly once");
    }

    private void tReplayPairingFrame() {
        TestEnvironment env = new TestEnvironment();
        env.dispenser.enterPairingMode();
        env.bus.clearSniffer();
        Kms.PairingPackage pkg = env.kms.issuePairingPackage(env.dispenserId, env.terminalId, 1_000_000);
        check(env.terminal.pairWith(pkg).success(), "pairing ok");
        // 抓出配对阶段帧，在新的维修窗口重放
        List<BusFrame> pairFrames = env.bus.sniffedFrames().stream()
                .filter(f -> f.type == Protocol.TYPE_PAIR).toList();
        check(!pairFrames.isEmpty(), "pairing frames observed");
        env.dispenser.enterPairingMode();
        env.attacker.replayOldPairingFrame(env.bus, pairFrames);
        check(hasEvent(env, ResultCode.PAIR_SEQ_STALE) || hasEvent(env, ResultCode.TICKET_INVALID)
                        || hasEvent(env, ResultCode.AUTH_FAILED),
                "old pairing frame rejected");
    }

    private void tUnpairedSilence() {
        TestEnvironment env = new TestEnvironment(); // 故意不配对
        long cash = env.hardware.totalDispensed();
        env.attacker.rawDispenseCommand(env.bus, env.terminalId, "X", 1000);
        env.attacker.garbageSecureFrame(env.bus, env.terminalId, 0);
        checkEq(env.hardware.totalDispensed(), cash, "unpaired module never moves cash");
        check(hasEvent(env, ResultCode.NOT_PAIRED), "not-paired event recorded");
    }

    private void tCrossDeviceToken() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        long cash = env.hardware.totalDispensed();
        // 第二台模块的 KDK：它的 K_AUTH 与 DSP-001 不同
        byte[] otherKdk = Crypto.randomBytes(32);
        env.kms.enrollDevice("DSP-OTHER", otherKdk);
        byte[] foreignToken = env.kms.issueOnlineAuthToken("DSP-OTHER", env.terminalId, "X-1", 1000, 300);
        Map<Integer, byte[]> cmd = Tlv.builder();
        cmd.put(Protocol.T_CMD, Tlv.intBytes(Protocol.CMD_DISPENSE));
        cmd.put(Protocol.T_TXN_ID, Tlv.utf8("X-1"));
        cmd.put(Protocol.T_AMOUNT, Tlv.longBytes(1000));
        cmd.put(Protocol.T_TOKEN_KIND, new byte[] {Protocol.TOKEN_KIND_ONLINE});
        cmd.put(Protocol.T_AUTH_TOKEN, foreignToken);
        Result r = sendAsTerminal(env, Tlv.encode(cmd));
        check(!r.success() && r.code() == ResultCode.AUTH_TOKEN_INVALID, "foreign token rejected: " + r);
        checkEq(env.hardware.totalDispensed(), cash, "no cross-device dispense");
    }

    // ------------------------------------------------------------------

    /** 以合法终端的通道密钥手工发送任意 TLV（模拟“终端已被攻破但通道仍合法”）。 */
    private Result sendAsTerminal(TestEnvironment env, byte[] tlvPayload) {
        return env.terminal.sendRawCommand(tlvPayload);
    }

    private static boolean hasEvent(TestEnvironment env, ResultCode code) {
        return env.dispenser.securityEvents().stream().anyMatch(e -> e.code() == code);
    }
}
