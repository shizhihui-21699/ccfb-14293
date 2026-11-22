package com.atm.security;

import java.util.HashMap;
import java.util.Map;

/**
 * 模拟非易失存储（Flash/安全元件分区）。
 * <p>
 * 业务对象“重启”时内存状态消失，但本存储内容保留——配对序号、通道计数器、
 * 离线额度、日志哈希链等安全状态都必须落在这里。测试可调用 {@link #tamper}
 * 模拟存储被物理改写，验证哈希链等篡改检测机制。
 */
public final class NonVolatileStore {

    private final String name;
    private final Map<String, byte[]> data = new HashMap<>();
    private int writeCount;

    public NonVolatileStore(String name) {
        this.name = name;
    }

    public String name() {
        return name;
    }

    public synchronized void putBytes(String key, byte[] value) {
        data.put(key, value == null ? null : value.clone());
        writeCount++;
    }

    public synchronized byte[] getBytes(String key) {
        byte[] v = data.get(key);
        return v == null ? null : v.clone();
    }

    public synchronized boolean contains(String key) {
        return data.containsKey(key);
    }

    public synchronized void putLong(String key, long v) {
        putBytes(key, com.atm.protocol.Tlv.longBytes(v));
    }

    public synchronized long getLong(String key, long dflt) {
        byte[] v = getBytes(key);
        return v == null ? dflt : com.atm.protocol.Tlv.asLong(v);
    }

    public synchronized void putString(String key, String v) {
        putBytes(key, v == null ? null : com.atm.protocol.Tlv.utf8(v));
    }

    public synchronized String getString(String key) {
        byte[] v = getBytes(key);
        return v == null ? null : com.atm.protocol.Tlv.asUtf8(v);
    }

    /** 测试专用：模拟攻击者对 Flash 内容的物理篡改。 */
    public synchronized void tamper(String key, byte[] forgedValue) {
        data.put(key, forgedValue == null ? null : forgedValue.clone());
    }

    /** 测试专用：模拟存储损坏/被擦除。 */
    public synchronized void erase(String key) {
        data.remove(key);
    }

    public int writeCount() {
        return writeCount;
    }
}
