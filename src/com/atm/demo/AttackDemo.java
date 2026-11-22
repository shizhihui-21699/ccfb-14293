package com.atm.demo;

import com.atm.attacker.AttackerDevice;
import com.atm.bus.BusFrame;
import com.atm.crypto.Crypto;
import com.atm.protocol.Protocol;
import com.atm.protocol.Result;
import com.atm.protocol.ResultCode;
import com.atm.protocol.Tlv;
import com.atm.security.SecureChannel;
import com.atm.tests.TestEnvironment;

import java.util.List;
import java.util.Map;

/**
 * 端到端攻防演示（不依赖测试框架，直接 main 运行）。
 * <p>
 * 唯一的安全判据是 {@code hardware.totalDispensed()}——任何攻击之后，
 * 实际出钞金额都必须严格等于“主机授权过的交易金额之和”。
 */
public final class AttackDemo {

    public static void main(String[] args) {
        TestEnvironment env = new TestEnvironment();
        var hw = env.hardware;
        var term = env.terminal;
        var atk = env.attacker;

        section("0. 合法维修配对（物理配对模式 + KMS 工单）");
        env.performLegitPairing();
        System.out.println("配对完成: terminal=" + term.isPaired() + " dispenser=" + env.dispenser.isPaired());

        section("1. 正常在线取款 1000（主机已授权）");
        Result r1 = term.dispenseOnline("TXN-1001", 1000, env.onlineToken("TXN-1001", 1000));
        report(r1, hw.totalDispensed());

        section("2. 黑盒攻击 A：撬开柜子，小电脑发裸出钞指令（原始漏洞复现）");
        atk.rawDispenseCommand(env.bus, env.terminalId, "HEIST-RAW", 50_000);
        System.out.println("  模块安全事件: " + latestEvent(env));
        System.out.println("  实际出钞总额 = " + hw.totalDispensed() + "（未增加 => 攻击失败）");

        section("3. 黑盒攻击 B：重放刚才抓到的合法出钞帧");
        env.bus.clearSniffer();
        term.dispenseOnline("TXN-1002", 600, env.onlineToken("TXN-1002", 600));
        List<BusFrame> captured = env.bus.sniffedFrames();
        BusFrame dispenseFrame = captured.stream().filter(f -> f.type == Protocol.TYPE_SECURE).findFirst().orElseThrow();
        for (int i = 0; i < 3; i++) {
            atk.replay(env.bus, dispenseFrame);
        }
        System.out.println("  重放 3 次后实际出钞总额 = " + hw.totalDispensed() + "（只算 TXN-1002 一次）");

        section("4. 黑盒攻击 C：篡改密文/帧头（GCM + AAD）");
        atk.tamperAndReplay(env.bus, dispenseFrame, 20);
        atk.tamperHeaderAndReplay(env.bus, dispenseFrame, "FAKE-TERM", 99);
        System.out.println("  实际出钞总额 = " + hw.totalDispensed() + "（未增加）");

        section("5. 黑盒攻击 D：替换业务电脑整机（无通道密钥、无主机授权能力）");
        var roguePc = new com.atm.terminal.TerminalApp("ROGUE-PC", env.clock, Crypto.randomBytes(32));
        roguePc.attach(env.bus);
        // 未配对终端直接调业务 API：在终端侧即被 NOT_PAIRED 拦截
        Result blocked = roguePc.heartbeat();
        System.out.println("  未配对终端调用结果 = " + blocked.code());
        // 直接注入伪造 GCM 帧
        SecureChannel bogus = new SecureChannel(Crypto.randomBytes(32));
        Map<Integer, byte[]> cmd = Map.of(
                Protocol.T_CMD, Tlv.intBytes(Protocol.CMD_DISPENSE),
                Protocol.T_TXN_ID, Tlv.utf8("HEIST-PC2"),
                Protocol.T_AMOUNT, Tlv.longBytes(9000),
                Protocol.T_TOKEN_KIND, new byte[] {Protocol.TOKEN_KIND_ONLINE},
                Protocol.T_AUTH_TOKEN, Crypto.randomBytes(60));
        byte[] sealed = bogus.seal(Protocol.TYPE_SECURE, "ROGUE-PC", Tlv.encode(cmd));
        env.bus.inject(new BusFrame(Protocol.TYPE_SECURE, "ROGUE-PC", 0, sealed));
        System.out.println("  替换 PC 后实际出钞总额 = " + hw.totalDispensed() + "（未增加）");

        section("6. 黑盒攻击 E：控制了合法终端，但伪造主机授权令牌");
        Map<Integer, byte[]> forged = Map.of(
                Protocol.T_CMD, Tlv.intBytes(Protocol.CMD_DISPENSE),
                Protocol.T_TXN_ID, Tlv.utf8("FORGED-AUTH"),
                Protocol.T_AMOUNT, Tlv.longBytes(2000),
                Protocol.T_TOKEN_KIND, new byte[] {Protocol.TOKEN_KIND_ONLINE},
                Protocol.T_AUTH_TOKEN, Crypto.randomBytes(60));
        Result fr = term.sendRawCommand(Tlv.encode(forged));
        System.out.println("  模块裁决 = " + fr.code() + "，实际出钞总额 = " + hw.totalDispensed());

        section("7. 断网离线交易：主机预签预算 5000/单笔≤1000");
        byte[] budget = env.offlineBudget(5000, 1000, 3600);
        Result o1 = term.dispenseOffline("OFF-1", 800, budget);
        Result o2 = term.dispenseOffline("OFF-2", 900, budget);
        Result o3 = term.dispenseOffline("OFF-3", 1500, budget); // 超单笔
        System.out.println("  OFF-1=" + o1.code() + " OFF-2=" + o2.code() + " OFF-3(超限)=" + o3.code());
        System.out.println("  离线实际出钞总额 = " + hw.totalDispensed());
        Result reconcile = term.uploadOfflineLog();
        System.out.println("  重连日志对账 = " + reconcile.code());

        section("结论");
        long authorized = 1000 + 600 + 800 + 900;
        System.out.println("  主机授权金额合计 = " + authorized);
        System.out.println("  机械实际出钞合计 = " + hw.totalDispensed());
        if (hw.totalDispensed() == authorized) {
            System.out.println("  ✅ 完全一致：所有黑盒攻击均未产生未授权出钞");
        } else {
            System.out.println("  ❌ 存在差额：安全机制失效！");
            System.exit(1);
        }
    }

    private static void section(String title) {
        System.out.println("\n----- " + title + " -----");
    }

    private static void report(Result r, long total) {
        System.out.println("  裁决=" + r.code() + " 累计出钞=" + total);
    }

    private static ResultCode latestEvent(TestEnvironment env) {
        var events = env.dispenser.securityEvents();
        return events.isEmpty() ? null : events.get(events.size() - 1).code();
    }
}
