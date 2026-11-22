package com.atm.tests;

import com.atm.attacker.AttackerDevice;
import com.atm.bus.BusFrame;
import com.atm.crypto.Crypto;
import com.atm.protocol.Protocol;
import com.atm.protocol.Result;
import com.atm.protocol.ResultCode;
import com.atm.protocol.Tlv;
import com.atm.security.Kms;

import java.util.List;
import java.util.Map;

/**
 * 配对协议安全测试：物理模式门控、票据伪造/重放/过期、序号单调性、
 * 跨设备票据挪用、整机替换后的重配对。
 */
public final class PairingTest extends AtmTest {

    public static List<AtmTest> suite() {
        return List.of(
                new PairingTest("未进入物理配对模式时配对消息被拒", () -> new PairingTest().tPairModeRequired()),
                new PairingTest("合法配对成功且通道可用", () -> new PairingTest().tLegitPairing()),
                new PairingTest("伪造票据无法配对", () -> new PairingTest().tForgedTicket()),
                new PairingTest("过期票据被拒", () -> new PairingTest().tExpiredTicket()),
                new PairingTest("旧序号票据被拒(单调配对序号)", () -> new PairingTest().tStaleSeq()),
                new PairingTest("同一票据不能重放配对两次", () -> new PairingTest().tTicketReplay()),
                new PairingTest("A 设备票据不能用于 B 设备", () -> new PairingTest().tCrossDeviceTicket()),
                new PairingTest("配对模式超时自动退出", () -> new PairingTest().tPairModeTimeout()),
                new PairingTest("替换业务电脑后凭新工单可重新配对", () -> new PairingTest().tReplaceTerminal()));
    }

    private final Runnable body;

    private PairingTest() {
        this.overrideName = null;
        this.body = null;
    }
    private final String overrideName;

    private PairingTest(String name, Runnable body) {
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

    private void tPairModeRequired() {
        TestEnvironment env = new TestEnvironment();
        // 不调用 enterPairingMode —— 模拟攻击者只能碰线缆、碰不到机内开关
        Kms.PairingPackage pkg = env.kms.issuePairingPackage(env.dispenserId, env.terminalId, 300);
        Result r = env.terminal.pairWith(pkg);
        check(!r.success(), "pairing must fail without physical pairing mode");
        check(!env.dispenser.isPaired(), "dispenser stays unpaired");
        check(hasEvent(env, ResultCode.PAIR_MODE_REQUIRED), "PAIR_MODE_REQUIRED event recorded");
        checkEq(env.hardware.totalDispensed(), 0L, "no cash movement");
    }

    private void tLegitPairing() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        check(env.dispenser.isPaired(), "dispenser paired");
        check(env.terminal.isPaired(), "terminal paired");
        Result hb = env.terminal.heartbeat();
        check(hb.success(), "heartbeat over secure channel works: " + hb);
    }

    private void tForgedTicket() {
        TestEnvironment env = new TestEnvironment();
        env.dispenser.enterPairingMode();
        Kms.PairingPackage real = env.kms.issuePairingPackage(env.dispenserId, env.terminalId, 300);
        // 攻击者拿不到 KMS 工单，用随机字节伪造票据
        Kms.PairingPackage forged = new Kms.PairingPackage(
                real.ticket(), Crypto.randomBytes(real.sealedTicket().length), real.kdkEnvelope());
        Result r = env.terminal.pairWith(forged);
        check(!r.success(), "forged ticket rejected");
        check(!env.dispenser.isPaired(), "no pairing established");
        check(hasEvent(env, ResultCode.TICKET_INVALID), "TICKET_INVALID recorded");
    }

    private void tExpiredTicket() {
        TestEnvironment env = new TestEnvironment();
        env.dispenser.enterPairingMode();
        Kms.PairingPackage pkg = env.kms.issuePairingPackage(env.dispenserId, env.terminalId, 60);
        env.clock.advance(120); // 越过票据有效期
        Result r = env.terminal.pairWith(pkg);
        check(!r.success(), "expired ticket rejected: " + r);
        check(hasEvent(env, ResultCode.TICKET_INVALID) || hasEvent(env, ResultCode.TICKET_EXPIRED),
                "expiry event recorded");
        check(!env.dispenser.isPaired(), "no pairing on expired ticket");
    }

    private void tStaleSeq() {
        TestEnvironment env = new TestEnvironment();
        // 先完成一次合法配对（消耗序号 1），旧工单保留
        env.dispenser.enterPairingMode();
        Kms.PairingPackage oldPkg = env.kms.issuePairingPackage(env.dispenserId, env.terminalId, 300);
        check(env.terminal.pairWith(oldPkg).success(), "initial pairing ok");
        // 模块再次进入配对模式（另一次维修窗口），攻击者重放序号 1 的旧工单
        env.dispenser.enterPairingMode();
        Result replay = env.terminal.pairWith(oldPkg);
        check(!replay.success(), "stale pairing seq rejected: " + replay);
        check(hasEvent(env, ResultCode.PAIR_SEQ_STALE), "PAIR_SEQ_STALE recorded");
        checkEq(env.dispenser.securityEvents().stream()
                        .filter(e -> e.code() == ResultCode.PAIR_SEQ_STALE).count(),
                1L, "exactly one stale-seq event");
    }

    private void tTicketReplay() {
        // 与序号单调性测试等价视角：同一工单在第二次维修窗口中重放
        tTicketReplayImpl();
    }

    private void tTicketReplayImpl() {
        TestEnvironment env = new TestEnvironment();
        env.dispenser.enterPairingMode();
        Kms.PairingPackage pkg = env.kms.issuePairingPackage(env.dispenserId, env.terminalId, 1_000_000);
        check(env.terminal.pairWith(pkg).success(), "first pairing succeeds");
        env.dispenser.enterPairingMode();
        Result replay = env.terminal.pairWith(pkg);
        check(!replay.success(), "replayed ticket rejected: " + replay);
        check(hasEvent(env, ResultCode.PAIR_SEQ_STALE), "replay blocked by monotonic seq");
    }

    private void tCrossDeviceTicket() {
        TestEnvironment env = new TestEnvironment();
        // 给另一台模块 DSP-OTHER 签的工单，拿来对 DSP-001 配对
        byte[] otherKdk = Crypto.randomBytes(32);
        env.kms.enrollDevice("DSP-OTHER", otherKdk);
        env.dispenser.enterPairingMode();
        Kms.PairingPackage other = env.kms.issuePairingPackage("DSP-OTHER", env.terminalId, 300);
        Result r = env.terminal.pairWith(other);
        check(!r.success(), "cross-device ticket rejected at terminal: " + r);
        check(!env.dispenser.isPaired(), "target device not paired");

        // 深度防御：即使攻击者绕过终端、把跨设备票据帧直接注入总线，
        // 模块侧票据 AAD 绑定了 dispenserId，仍必须拒绝
        Map<Integer, byte[]> begin = Tlv.builder();
        begin.put(Protocol.T_CMD, Tlv.intBytes(Protocol.PAIR_BEGIN));
        begin.put(Protocol.T_TERMINAL_ID, Tlv.utf8(env.terminalId));
        begin.put(Protocol.T_DISPENSER_ID, Tlv.utf8(env.dispenserId));
        begin.put(Protocol.T_PAIR_SEQ, Tlv.longBytes(other.ticket().pairSeq()));
        begin.put(Protocol.T_EXPIRY, Tlv.longBytes(other.ticket().expiryEpochSec()));
        begin.put(Protocol.T_TICKET, other.sealedTicket());
        byte[] sealed = Crypto.aesGcmSeal(env.keys.kPair(),
                BusFrame.buildAad(Protocol.TYPE_PAIR, env.terminalId, 0), Tlv.encode(begin));
        env.bus.inject(new BusFrame(Protocol.TYPE_PAIR, env.terminalId, 0, sealed));
        check(hasEvent(env, ResultCode.TICKET_INVALID), "module-side AAD binding rejects foreign ticket");
        check(!env.dispenser.isPaired(), "module still unpaired after injected foreign ticket");
    }

    private void tPairModeTimeout() {
        TestEnvironment env = new TestEnvironment();
        env.dispenser.enterPairingMode();
        check(env.dispenser.isPairingMode(), "pairing mode on");
        env.clock.advance(301);
        check(!env.dispenser.isPairingMode(), "pairing mode auto-exits after TTL");
        Kms.PairingPackage pkg = env.kms.issuePairingPackage(env.dispenserId, env.terminalId, 300);
        Result r = env.terminal.pairWith(pkg);
        check(!r.success(), "pairing rejected after window closed");
    }

    private void tReplaceTerminal() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        // 业务电脑故障，换新电脑；KMS 按维修工单签发序号 2 的新包
        env.dispenser.enterPairingMode();
        TerminalApp2 replacement = new TerminalApp2("TERM-B", env);
        Kms.PairingPackage pkg = env.kms.issuePairingPackage(env.dispenserId, "TERM-B", 300);
        Result r = replacement.app.pairWith(pkg);
        check(r.success(), "replacement terminal pairs with fresh work order: " + r);
        // 旧终端的通道密钥应当已失效：模块只与最新配对方保持安全关系
        Result old = env.terminal.heartbeat();
        check(!old.success() || old.code() == ResultCode.AUTH_FAILED,
                "old terminal's channel must not be silently trusted");
        Result now = replacement.app.heartbeat();
        check(now.success(), "new terminal channel works");
    }

    private static boolean hasEvent(TestEnvironment env, ResultCode code) {
        return env.dispenser.securityEvents().stream().anyMatch(e -> e.code() == code);
    }

    /** 装配第二台终端的小夹具（已在 KMS 入网）。 */
    private record TerminalApp2(com.atm.terminal.TerminalApp app) {
        TerminalApp2(String id, TestEnvironment env) {
            this(new com.atm.terminal.TerminalApp(id, env.clock, env.kms.enrollTerminal(id)));
            app.attach(env.bus);
        }
    }
}
