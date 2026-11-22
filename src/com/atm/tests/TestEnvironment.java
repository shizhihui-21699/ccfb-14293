package com.atm.tests;

import com.atm.attacker.AttackerDevice;
import com.atm.bus.PhysicalBus;
import com.atm.crypto.Crypto;
import com.atm.dispenser.CashDispenser;
import com.atm.hardware.HardwareSimulator;
import com.atm.security.DeviceKeys;
import com.atm.security.Kms;
import com.atm.security.NonVolatileStore;
import com.atm.terminal.TerminalApp;
import com.atm.util.SimClock;

/**
 * 标准测试环境：一台已产线注入的出钞模块、KMS、业务终端、攻击者小电脑、
 * 物理总线、可控时钟。各套件按需调用配对流程。
 */
public final class TestEnvironment {

    public static final long T0 = 1_700_000_000L;

    public final SimClock clock = new SimClock(T0);
    public final PhysicalBus bus = new PhysicalBus();
    public final Kms kms = new Kms(clock);
    public final NonVolatileStore dispenserNvm = new NonVolatileStore("dispenser-nvm");
    public final HardwareSimulator hardware = new HardwareSimulator();
    public final CashDispenser dispenser;
    public final TerminalApp terminal;
    public final AttackerDevice attacker = new AttackerDevice("attacker-pi");

    public final String dispenserId = "DSP-001";
    public final String terminalId = "TERM-A";
    public final DeviceKeys keys;

    public TestEnvironment() {
        byte[] kdk = Crypto.randomBytes(32);
        this.keys = kms.enrollDevice(dispenserId, kdk);
        hardware.addCassette("C1", 100, 500);   // 1 元 × 500
        hardware.addCassette("C2", 500, 200);   // 5 元 × 200
        hardware.addCassette("C3", 1000, 100);  // 10 元 × 100
        this.dispenser = new CashDispenser(dispenserId, keys, dispenserNvm, hardware, clock);
        dispenser.attach(bus);
        // 终端入网：KMS 登记身份密钥，终端侧副本由安全元件保护
        this.terminalIdentityKey = kms.enrollTerminal(terminalId);
        this.terminal = new TerminalApp(terminalId, clock, terminalIdentityKey);
        terminal.attach(bus);
        bus.attach(attacker);
    }

    public final byte[] terminalIdentityKey;

    /** 标准合法配对（含物理配对模式操作）。 */
    public void performLegitPairing() {
        dispenser.enterPairingMode();
        Kms.PairingPackage pkg = kms.issuePairingPackage(dispenserId, terminalId, 300);
        var r = terminal.pairWith(pkg);
        if (!r.success()) {
            throw new IllegalStateException("legit pairing failed: " + r);
        }
    }

    public byte[] onlineToken(String txnId, long amount) {
        return kms.issueOnlineAuthToken(dispenserId, terminalId, txnId, amount, 120);
    }

    public byte[] offlineBudget(long total, long perTxn, long windowSeconds) {
        return kms.issueOfflineBudget(dispenserId, terminalId, total, perTxn,
                clock.now(), clock.now() + windowSeconds);
    }
}
