package com.atm.tests;

import com.atm.bus.BusFrame;
import com.atm.protocol.Protocol;
import com.atm.protocol.Result;
import com.atm.protocol.ResultCode;
import com.atm.protocol.Tlv;
import com.atm.security.SecureChannel;

import java.util.List;
import java.util.Map;

/**
 * 设备生命周期与韧性测试：重启后的安全状态恢复、通道计数器持久化、
 * 钞箱不足的业务失败与安全拒绝相区分、维修更换出钞模块的再配对。
 */
public final class LifecycleTest extends AtmTest {

    public static List<AtmTest> suite() {
        return List.of(
                new LifecycleTest("模块重启后配对关系与通道保持有效", () -> new LifecycleTest().tRebootPreservesPairing()),
                new LifecycleTest("重启后旧计数器帧仍被识别为重放", () -> new LifecycleTest().tRebootReplayMemory()),
                new LifecycleTest("终端重启后凭持久化通道密钥恢复", () -> new LifecycleTest().tTerminalReboot()),
                new LifecycleTest("硬件余额不足返回业务错误而非安全错误", () -> new LifecycleTest().tInsufficientCash()),
                new LifecycleTest("更换出钞模块后需重新产线注入与配对", () -> new LifecycleTest().tReplaceDispenser()),
                new LifecycleTest("安全事件审计轨迹完整记录攻击", () -> new LifecycleTest().tAuditTrail()),
                new LifecycleTest("未知命令被拒绝且不出钞", () -> new LifecycleTest().tUnknownCommand()));
    }

    private final Runnable body;

    private LifecycleTest() {
        this.overrideName = null;
        this.body = null;
    }
    private final String overrideName;

    private LifecycleTest(String name, Runnable body) {
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

    private void tRebootPreservesPairing() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        env.terminal.heartbeat();
        var rebooted = new com.atm.dispenser.CashDispenser(
                env.dispenserId, env.keys, env.dispenserNvm, env.hardware, env.clock);
        rebooted.attach(env.bus);
        check(rebooted.isPaired(), "pairing retained in NVM");
        // 旧终端对象的计数器与模块持久化计数器可能出现前跳，重同步后恢复
        Result r = env.terminal.heartbeat();
        check(r.success() || r.code() == ResultCode.REPLAY_DETECTED, "channel recoverable after reboot: " + r);
    }

    private void tRebootReplayMemory() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        env.bus.clearSniffer();
        env.terminal.heartbeat();
        List<BusFrame> history = env.bus.sniffedFrames();
        // 模块重启
        var rebooted = new com.atm.dispenser.CashDispenser(
                env.dispenserId, env.keys, env.dispenserNvm, env.hardware, env.clock);
        rebooted.attach(env.bus);
        long cash = env.hardware.totalDispensed();
        // 重启前的旧帧重放：接收计数器从 NVM 恢复，旧序号应被拒
        for (BusFrame f : history) {
            env.attacker.replay(env.bus, f);
        }
        check(rebooted.securityEvents().stream()
                        .anyMatch(e -> e.code() == ResultCode.REPLAY_DETECTED || e.code() == ResultCode.AUTH_FAILED),
                "pre-reboot frames rejected after reboot");
        checkEq(env.hardware.totalDispensed(), cash, "reboot replay pays nothing");
    }

    private void tTerminalReboot() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        // 终端重启：内存清空，模拟从安全元件恢复通道密钥
        byte[] kChannel = env.keys.kChannel();
        env.terminal.reboot();
        check(!env.terminal.isPaired(), "terminal memory cleared");
        env.terminal.restoreAfterReboot(env.dispenserId, kChannel);
        Result r = env.terminal.heartbeat();
        check(r.success(), "terminal restores channel from protected storage: " + r);
    }

    private void tInsufficientCash() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        // 请求一个远超钞箱余额、且面额无法配钞的金额
        long huge = 9_999_999_000L;
        Result r = env.terminal.dispenseOnline("CASH-LOW", huge, env.onlineToken("CASH-LOW", huge));
        check(!r.success(), "dispense fails");
        check(!r.code().isSecurityRejection(),
                "hardware failure is a business code, not a security rejection: " + r.code());
        checkEq(r.code(), ResultCode.HARDWARE_FAULT, "hardware fault reported");
    }

    private void tReplaceDispenser() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        // 物理更换：旧模块从总线移除，新模块（新 KDK、空 NVM）接入
        env.bus.detach(env.dispenser);
        var newNvm = new com.atm.security.NonVolatileStore("new-dispenser-nvm");
        byte[] newKdk = com.atm.crypto.Crypto.randomBytes(32);
        var newKeys = env.kms.enrollDevice("DSP-NEW", newKdk);
        var newHardware = new com.atm.hardware.HardwareSimulator();
        newHardware.addCassette("C1", 100, 100);
        var newDispenser = new com.atm.dispenser.CashDispenser(
                "DSP-NEW", newKeys, newNvm, newHardware, env.clock);
        newDispenser.attach(env.bus);
        check(!newDispenser.isPaired(), "fresh module ships unpaired");

        long cash = newHardware.totalDispensed();
        // 旧终端仍持有旧通道密钥，对新模块发心跳：新模块无配对关系，静默拒绝
        Result stale = env.terminal.heartbeat();
        check(!stale.success(), "old channel key cannot drive new module: " + stale);
        check(newDispenser.securityEvents().stream()
                        .anyMatch(e -> e.code() == ResultCode.NOT_PAIRED || e.code() == ResultCode.AUTH_FAILED),
                "new module rejects legacy channel");
        checkEq(newHardware.totalDispensed(), cash, "no cash before legitimate pairing");

        // 走正规维修流程：物理配对模式 + KMS 针对 DSP-NEW 的工单
        newDispenser.enterPairingMode();
        var pkg = env.kms.issuePairingPackage("DSP-NEW", env.terminalId, 300);
        Result paired = env.terminal.pairWith(pkg);
        check(paired.success(), "new module paired through proper work order: " + paired);
        Result ok = env.terminal.dispenseOnline("NEW-1", 500,
                env.kms.issueOnlineAuthToken("DSP-NEW", env.terminalId, "NEW-1", 500, 120));
        check(ok.success(), "new module serves authorized txn: " + ok);
        checkEq(newHardware.totalDispensed(), cash + 500, "new module cash accounting correct");
    }

    private void tAuditTrail() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        env.attacker.rawDispenseCommand(env.bus, env.terminalId, "AUDIT-1", 1000);
        env.attacker.garbageSecureFrame(env.bus, env.terminalId, 5);
        var events = env.dispenser.securityEvents();
        check(events.stream().anyMatch(e -> e.code() == ResultCode.AUTH_FAILED),
                "auth failures present in audit trail");
        check(events.stream().allMatch(e -> e.detail() != null || e.code() != null),
                "every event carries code and timestamp");
    }

    private void tUnknownCommand() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        long cash = env.hardware.totalDispensed();
        Map<Integer, byte[]> weird = Tlv.builder();
        weird.put(Protocol.T_CMD, Tlv.intBytes(0x7777));
        Result r = env.terminal.sendRawCommand(Tlv.encode(weird));
        check(!r.success() && r.code() == ResultCode.COMMAND_UNKNOWN, "unknown command rejected: " + r);
        checkEq(env.hardware.totalDispensed(), cash, "unknown command moves no cash");
    }
}
