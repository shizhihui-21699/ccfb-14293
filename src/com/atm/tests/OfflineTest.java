package com.atm.tests;

import com.atm.protocol.Result;
import com.atm.protocol.ResultCode;
import com.atm.security.OfflineLog;

import java.util.List;

/**
 * 断网场景测试：预签名预算凭证、模块本地额度强制、时间窗、
 * 哈希链日志、重连对账、日志篡改检测。
 */
public final class OfflineTest extends AtmTest {

    public static List<AtmTest> suite() {
        return List.of(
                new OfflineTest("离线预算内多笔交易成功并逐笔记账", () -> new OfflineTest().tOfflineHappyPath()),
                new OfflineTest("超出单笔上限被拒", () -> new OfflineTest().tPerTxnLimit()),
                new OfflineTest("累计预算耗尽后拒绝", () -> new OfflineTest().tBudgetExhausted()),
                new OfflineTest("预算时间窗外拒绝", () -> new OfflineTest().tWindowClosed()),
                new OfflineTest("离线txnId重放不重复出钞", () -> new OfflineTest().tOfflineReplay()),
                new OfflineTest("重连后日志对账一致", () -> new OfflineTest().tLogReconcile()),
                new OfflineTest("终端日志被篡改后对账失败", () -> new OfflineTest().tLogTamperDetected()),
                new OfflineTest("模块重启后离线计数与已花额度保持", () -> new OfflineTest().tPersistenceAcrossReboot()),
                new OfflineTest("无预算凭证时离线出钞被拒", () -> new OfflineTest().tNoBudgetNoCash()));
    }

    private final Runnable body;

    private OfflineTest() {
        this.overrideName = null;
        this.body = null;
    }
    private final String overrideName;

    private OfflineTest(String name, Runnable body) {
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

    private void tOfflineHappyPath() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        byte[] budget = env.offlineBudget(5000, 1000, 3600);
        long cash = env.hardware.totalDispensed();
        Result r1 = env.terminal.dispenseOffline("OFF-1", 800, budget);
        Result r2 = env.terminal.dispenseOffline("OFF-2", 700, budget);
        check(r1.success() && r2.success(), "offline txns within budget accepted");
        checkEq(env.hardware.totalDispensed(), cash + 1500, "cash matches offline spends");
        checkEq(env.terminal.offlineLog().size(), 2, "two chained log entries on terminal");
        // 哈希链自检
        Result chain = OfflineLog.verify(env.terminal.offlineLog().entries());
        check(chain.success(), "hash chain intact: " + chain);
    }

    private void tPerTxnLimit() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        byte[] budget = env.offlineBudget(10_000, 1000, 3600);
        long cash = env.hardware.totalDispensed();
        Result r = env.terminal.dispenseOffline("OFF-BIG", 1500, budget);
        check(!r.success() && r.code() == ResultCode.OFFLINE_QUOTA_EXCEEDED, "per-txn cap enforced: " + r);
        checkEq(env.hardware.totalDispensed(), cash, "no cash over per-txn cap");
    }

    private void tBudgetExhausted() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        byte[] budget = env.offlineBudget(2000, 1000, 3600);
        check(env.terminal.dispenseOffline("OFF-1", 1000, budget).success(), "first ok");
        check(env.terminal.dispenseOffline("OFF-2", 1000, budget).success(), "second ok");
        long cash = env.hardware.totalDispensed();
        Result third = env.terminal.dispenseOffline("OFF-3", 500, budget);
        check(!third.success() && third.code() == ResultCode.OFFLINE_BUDGET_EXHAUSTED,
                "budget exhaustion enforced: " + third);
        checkEq(env.hardware.totalDispensed(), cash, "no cash beyond budget");
    }

    private void tWindowClosed() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        byte[] budget = env.offlineBudget(5000, 1000, 600);
        env.clock.advance(601);
        long cash = env.hardware.totalDispensed();
        Result r = env.terminal.dispenseOffline("OFF-LATE", 500, budget);
        check(!r.success() && r.code() == ResultCode.AUTH_TOKEN_EXPIRED, "window closure enforced: " + r);
        checkEq(env.hardware.totalDispensed(), cash, "no cash outside window");
    }

    private void tOfflineReplay() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        byte[] budget = env.offlineBudget(5000, 1000, 3600);
        check(env.terminal.dispenseOffline("OFF-R", 600, budget).success(), "first offline txn ok");
        long cash = env.hardware.totalDispensed();
        for (int i = 0; i < 3; i++) {
            Result dup = env.terminal.dispenseOffline("OFF-R", 600, budget);
            check(!dup.success() && dup.code() == ResultCode.TXN_ALREADY_EXECUTED,
                    "offline txn replay idempotently rejected: " + dup);
        }
        checkEq(env.hardware.totalDispensed(), cash, "offline replay pays nothing extra");
    }

    private void tLogReconcile() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        byte[] budget = env.offlineBudget(5000, 1000, 3600);
        env.terminal.dispenseOffline("OFF-1", 900, budget);
        env.terminal.dispenseOffline("OFF-2", 300, budget);
        // 网络恢复，终端把日志上送，模块用自身副本核对
        Result reconcile = env.terminal.uploadOfflineLog();
        check(reconcile.success(), "reconciliation succeeds with matching chains: " + reconcile);
    }

    private void tLogTamperDetected() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        byte[] budget = env.offlineBudget(5000, 1000, 3600);
        env.terminal.dispenseOffline("OFF-1", 900, budget);
        env.terminal.dispenseOffline("OFF-2", 300, budget);
        // 攻击者在终端侧抹掉一条日志（模拟掩盖盗取痕迹）
        List<OfflineLog.Entry> tampered = env.terminal.offlineLog().entries();
        tampered.remove(0);
        // 直接用模块的校验器验证残缺链
        Result direct = OfflineLog.verify(tampered);
        check(!direct.success() && direct.code() == ResultCode.LOG_TAMPERED, "truncated chain detected");

        // 模块 NVM 中的日志被物理改写：篡改金额字段（落在记录内部，破坏哈希链）
        byte[] raw = env.dispenserNvm.getBytes("offlineLog");
        check(raw != null, "module persisted offline log");
        byte[] forged = raw.clone();
        // 跳过 4 字节 count，定位第一条记录的 amount 字段（idx:8 + txnId 长度前缀 4 + 字符串）
        // 直接翻转记录中部一个数据字节，保证既不破坏长度前缀、又改变链内容
        int dataByte = forged.length / 2;
        forged[dataByte] ^= 0x7F;
        env.dispenserNvm.tamper("offlineLog", forged);
        // 重建模块实例：boot 阶段的哈希链自检必须发现篡改并拒绝启动
        boolean caught = false;
        try {
            new com.atm.dispenser.CashDispenser(env.dispenserId, env.keys,
                    env.dispenserNvm, env.hardware, env.clock);
        } catch (IllegalStateException e) {
            caught = true;
        }
        check(caught, "tampered NVM log detected at boot");
    }

    private void tPersistenceAcrossReboot() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        // 总额度 5000、单笔上限 5000，这样超额只可能由“累计额度”触发
        byte[] budget = env.offlineBudget(5000, 5000, 3600);
        env.terminal.dispenseOffline("OFF-1", 1000, budget);
        // 模块“断电重启”：内存对象重建，NVM 保留
        var rebooted = new com.atm.dispenser.CashDispenser(
                env.dispenserId, env.keys, env.dispenserNvm, env.hardware, env.clock);
        rebooted.attach(env.bus);
        check(rebooted.isPaired(), "pairing survives reboot");
        long cash = env.hardware.totalDispensed();
        // 已花 1000（持久化），再花 4500 会超过总额度 5000，必须被累计额度拦截
        Result r = env.terminal.dispenseOffline("OFF-2", 4500, budget);
        check(!r.success() && r.code() == ResultCode.OFFLINE_BUDGET_EXHAUSTED,
                "spent quota persists across reboot: " + r);
        checkEq(env.hardware.totalDispensed(), cash, "reboot state prevents overspend");
        // 小金额仍在剩余额度内（1000 + 500 <= 5000）
        Result ok = env.terminal.dispenseOffline("OFF-3", 500, budget);
        check(ok.success(), "remaining budget usable after reboot: " + ok);
    }

    private void tNoBudgetNoCash() {
        TestEnvironment env = new TestEnvironment();
        env.performLegitPairing();
        long cash = env.hardware.totalDispensed();
        // 没有任何离线预算凭证，攻击者控制终端后尝试直接离线出钞
        Result r = env.terminal.sendRawCommand(com.atm.protocol.Tlv.encode(java.util.Map.of(
                com.atm.protocol.Protocol.T_CMD, com.atm.protocol.Tlv.intBytes(com.atm.protocol.Protocol.CMD_DISPENSE),
                com.atm.protocol.Protocol.T_TXN_ID, com.atm.protocol.Tlv.utf8("NO-BUDGET"),
                com.atm.protocol.Protocol.T_AMOUNT, com.atm.protocol.Tlv.longBytes(500),
                com.atm.protocol.Protocol.T_TOKEN_KIND,
                new byte[] {com.atm.protocol.Protocol.TOKEN_KIND_OFFLINE_BUDGET},
                com.atm.protocol.Protocol.T_AUTH_TOKEN, new byte[0])));
        check(!r.success(), "offline dispense without budget rejected: " + r);
        checkEq(env.hardware.totalDispensed(), cash, "no cash without budget");
    }
}
