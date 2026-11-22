package com.atm.security;

import com.atm.crypto.Crypto;
import com.atm.protocol.Protocol;
import com.atm.protocol.Tlv;
import com.atm.protocol.ResultCode;
import com.atm.protocol.Result;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 离线交易日志（哈希链）。
 * <p>
 * 每笔离线出钞产生一条记录，记录包含严格递增的 index，且每条记录携带
 * 前一条记录的哈希（链头存放在 NVM）。任何删除、插入、改写都会破坏链，
 * 重连对账时主机可立即发现。终端与模块各自维护一条相同的链，互相印证。
 */
public final class OfflineLog {

    public record Entry(long index,
                        String txnId,
                        long amountMinor,
                        long timestampSec,
                        byte[] prevHash,
                        byte[] entryHash) {
    }

    private final List<Entry> entries = new ArrayList<>();
    private byte[] headHash = Crypto.sha256(Tlv.utf8("OFFLINE-LOG-GENESIS/V1"));

    /**
     * 追加一条离线交易。index 必须严格递增（模块侧由 NVM 持久化的计数器保证）。
     */
    public synchronized Entry append(long expectedIndex, String txnId, long amountMinor, long timestampSec) {
        long actualIndex = entries.size();
        if (expectedIndex != actualIndex) {
            throw new IllegalArgumentException("index gap: expected " + actualIndex + " got " + expectedIndex);
        }
        byte[] prev = headHash.clone();
        Map<Integer, byte[]> body = Tlv.builder();
        body.put(Protocol.T_OFFLINE_INDEX, Tlv.longBytes(expectedIndex));
        body.put(Protocol.T_TXN_ID, Tlv.utf8(txnId));
        body.put(Protocol.T_AMOUNT, Tlv.longBytes(amountMinor));
        body.put(Protocol.T_EXPIRY, Tlv.longBytes(timestampSec));
        body.put(Protocol.T_DETAIL, prev);
        byte[] hash = Crypto.sha256(Tlv.encode(body));
        Entry e = new Entry(expectedIndex, txnId, amountMinor, timestampSec, prev, hash);
        entries.add(e);
        headHash = hash;
        return e;
    }

    public synchronized byte[] headHash() {
        return headHash.clone();
    }

    public synchronized int size() {
        return entries.size();
    }

    public synchronized List<Entry> entries() {
        return new ArrayList<>(entries);
    }

    public synchronized Entry get(long index) {
        if (index < 0 || index >= entries.size()) {
            return null;
        }
        return entries.get((int) index);
    }

    /**
     * 独立校验整条链：重放哈希计算，检测任何篡改/断链。
     * 主机重连对账与模块启动自检都调用它。
     */
    public static Result verify(List<Entry> log) {
        byte[] expectedPrev = Crypto.sha256(Tlv.utf8("OFFLINE-LOG-GENESIS/V1"));
        long expectedIndex = 0;
        for (Entry e : log) {
            if (e.index() != expectedIndex) {
                return Result.reject(ResultCode.LOG_TAMPERED,
                        "index discontinuity at " + e.index());
            }
            if (!Crypto.constantTimeEquals(e.prevHash(), expectedPrev)) {
                return Result.reject(ResultCode.LOG_TAMPERED,
                        "broken prev-hash link at index " + e.index());
            }
            Map<Integer, byte[]> body = Tlv.builder();
            body.put(Protocol.T_OFFLINE_INDEX, Tlv.longBytes(e.index()));
            body.put(Protocol.T_TXN_ID, Tlv.utf8(e.txnId()));
            body.put(Protocol.T_AMOUNT, Tlv.longBytes(e.amountMinor()));
            body.put(Protocol.T_EXPIRY, Tlv.longBytes(e.timestampSec()));
            body.put(Protocol.T_DETAIL, expectedPrev);
            byte[] recomputed = Crypto.sha256(Tlv.encode(body));
            if (!Crypto.constantTimeEquals(recomputed, e.entryHash())) {
                return Result.reject(ResultCode.LOG_TAMPERED,
                        "entry hash mismatch at index " + e.index());
            }
            expectedPrev = recomputed;
            expectedIndex++;
        }
        return Result.ok();
    }
}
