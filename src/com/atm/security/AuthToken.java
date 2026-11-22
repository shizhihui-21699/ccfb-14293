package com.atm.security;

import com.atm.crypto.Crypto;
import com.atm.protocol.Protocol;
import com.atm.protocol.Tlv;

import java.util.Map;

/**
 * 主机授权令牌。出钞命令的合法性最终由它证明——
 * 终端只是令牌的“搬运工”，自身无权让模块出钞。
 * <p>
 * 在线令牌按单笔交易签发（txnId + 金额强绑定）；
 * 离线令牌是预算凭证（时间窗 + 累计/单笔限额），由模块本地记账强制执行。
 * 两类令牌都用只有 KMS（主机域）与出钞模块持有的 K_AUTH 密封，
 * 被替换的业务电脑没有任何手段伪造。
 */
public record AuthToken(String dispenserId,
                        String terminalId,
                        String txnId,          // 离线预算令牌为 "*"
                        long amountMinor,      // 离线时为预算总额
                        long perTxnLimitMinor, // 在线令牌等于 amount；离线为单笔上限
                        long issueEpochSec,
                        long expiryEpochSec,
                        long windowStart,      // 在线令牌为 0
                        long windowEnd,        // 在线令牌为 0
                        long nonce) {

    public boolean offlineBudget() {
        return "*".equals(txnId);
    }

    public byte[] seal(byte[] kAuth) {
        Map<Integer, byte[]> f = Tlv.builder();
        f.put(Protocol.T_DISPENSER_ID, Tlv.utf8(dispenserId));
        f.put(Protocol.T_TERMINAL_ID, Tlv.utf8(terminalId));
        f.put(Protocol.T_TXN_ID, Tlv.utf8(txnId));
        f.put(Protocol.T_AMOUNT, Tlv.longBytes(amountMinor));
        f.put(Protocol.T_STATUS, Tlv.longBytes(perTxnLimitMinor));
        f.put(Protocol.T_EXPIRY, Tlv.longBytes(expiryEpochSec));
        f.put(Protocol.T_WINDOW_START, Tlv.longBytes(windowStart));
        f.put(Protocol.T_WINDOW_END, Tlv.longBytes(windowEnd));
        f.put(Protocol.T_NONCE, Tlv.longBytes(nonce));
        f.put(Protocol.T_DETAIL, Tlv.longBytes(issueEpochSec));
        // AAD 绑定最关键的路由字段，防止令牌在不同设备/交易间挪用
        byte[] aad = Tlv.encode(Map.of(
                Protocol.T_DISPENSER_ID, Tlv.utf8(dispenserId),
                Protocol.T_TERMINAL_ID, Tlv.utf8(terminalId),
                Protocol.T_TXN_ID, Tlv.utf8(txnId)));
        return Crypto.aesGcmSeal(kAuth, aad, Tlv.encode(f));
    }

    public static AuthToken open(byte[] kAuth,
                                 String expectedDispenserId,
                                 String expectedTerminalId,
                                 String expectedTxnId,
                                 byte[] sealed) {
        byte[] aad = Tlv.encode(Map.of(
                Protocol.T_DISPENSER_ID, Tlv.utf8(expectedDispenserId),
                Protocol.T_TERMINAL_ID, Tlv.utf8(expectedTerminalId),
                Protocol.T_TXN_ID, Tlv.utf8(expectedTxnId)));
        byte[] body = Crypto.aesGcmOpen(kAuth, aad, sealed);
        Map<Integer, byte[]> f = Tlv.decode(body);
        AuthToken t = new AuthToken(
                Tlv.asUtf8(f.get(Protocol.T_DISPENSER_ID)),
                Tlv.asUtf8(f.get(Protocol.T_TERMINAL_ID)),
                Tlv.asUtf8(f.get(Protocol.T_TXN_ID)),
                Tlv.asLong(f.get(Protocol.T_AMOUNT)),
                Tlv.asLong(f.get(Protocol.T_STATUS)),
                Tlv.asLong(f.get(Protocol.T_DETAIL)),
                Tlv.asLong(f.get(Protocol.T_EXPIRY)),
                Tlv.asLong(f.get(Protocol.T_WINDOW_START)),
                Tlv.asLong(f.get(Protocol.T_WINDOW_END)),
                Tlv.asLong(f.get(Protocol.T_NONCE)));
        if (!t.dispenserId.equals(expectedDispenserId)
                || !t.terminalId.equals(expectedTerminalId)
                || !t.txnId.equals(expectedTxnId)) {
            throw new Crypto.AuthFailureException("token binding mismatch");
        }
        return t;
    }
}
