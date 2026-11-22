package com.atm.terminal;

import com.atm.dispenser.CashDispenser;
import com.atm.security.OfflineLog;
import com.atm.protocol.Tlv;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 终端侧的持久化模拟：保存配对通道密钥（真实部署中位于 TPM/安全元件）
 * 与离线日志副本。测试中独立于模块 NVM 存在，可被分别篡改/擦除。
 */
final class NonVolatileTerminalStore {

    private final Map<String, byte[]> data = new HashMap<>();
    private final String name;

    NonVolatileTerminalStore(String name) {
        this.name = name;
    }

    void savePaired(String dispenserId, byte[] kChannel) {
        data.put("dispenserId", Tlv.utf8(dispenserId));
        data.put("kChannel", kChannel.clone());
    }

    String pairedDispenser() {
        byte[] v = data.get("dispenserId");
        return v == null ? null : Tlv.asUtf8(v);
    }

    byte[] channelKey() {
        byte[] v = data.get("kChannel");
        return v == null ? null : v.clone();
    }

    void persistOfflineLog(List<OfflineLog.Entry> entries) {
        data.put("offlineLog", com.atm.dispenser.CashDispenser.serializeLog(entries));
    }

    List<OfflineLog.Entry> loadOfflineLog() {
        byte[] raw = data.get("offlineLog");
        if (raw == null) {
            return new ArrayList<>();
        }
        return CashDispenser.deserializeLog(raw);
    }
}
