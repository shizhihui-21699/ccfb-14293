package com.atm.security;

import com.atm.crypto.Crypto;
import com.atm.protocol.Protocol;
import com.atm.protocol.Tlv;

import java.util.Map;

/**
 * 配对票据（KMS 签发，出钞模块验证）。
 * <p>
 * 票据内容用目标出钞模块的 K_PAIR 做 GCM 密封，且把票据关键字段同时作为 AAD：
 * 攻击者既无法伪造（无 K_PAIR），也无法把一张票据套用到别的设备或别的配对序号上
 * （AAD 中的设备标识/序号不匹配则 tag 校验失败）。
 * 票据一次性、短时效，并受模块内单调递增 pairSeq 约束，重放旧票据会被拒绝。
 */
public record PairingTicket(String dispenserId,
                            String terminalId,
                            long pairSeq,
                            long nonce,
                            long expiryEpochSec) {

    /** 明文头部（AAD）：模块在解密前就能读取并比对自身状态。 */
    public byte[] aad() {
        return Tlv.encode(Map.of(
                Protocol.T_DISPENSER_ID, Tlv.utf8(dispenserId),
                Protocol.T_TERMINAL_ID, Tlv.utf8(terminalId),
                Protocol.T_PAIR_SEQ, Tlv.longBytes(pairSeq),
                Protocol.T_EXPIRY, Tlv.longBytes(expiryEpochSec)));
    }

    public byte[] seal(byte[] kPair) {
        Map<Integer, byte[]> body = Tlv.builder();
        body.put(Protocol.T_DISPENSER_ID, Tlv.utf8(dispenserId));
        body.put(Protocol.T_TERMINAL_ID, Tlv.utf8(terminalId));
        body.put(Protocol.T_PAIR_SEQ, Tlv.longBytes(pairSeq));
        body.put(Protocol.T_NONCE, Tlv.longBytes(nonce));
        body.put(Protocol.T_EXPIRY, Tlv.longBytes(expiryEpochSec));
        return Crypto.aesGcmSeal(kPair, aad(), Tlv.encode(body));
    }

    /**
     * 验证并解析票据。任何字段被篡改/票据不属于本模块/票据过期都会抛
     * {@link Crypto.AuthFailureException}。pairSeq 单调性由模块另行检查。
     */
    public static PairingTicket open(byte[] kPair,
                                     String expectedDispenserId,
                                     String claimedTerminalId,
                                     long claimedPairSeq,
                                     long claimedExpiry,
                                     byte[] sealed,
                                     long nowEpochSec) {
        byte[] aad = Tlv.encode(Map.of(
                Protocol.T_DISPENSER_ID, Tlv.utf8(expectedDispenserId),
                Protocol.T_TERMINAL_ID, Tlv.utf8(claimedTerminalId),
                Protocol.T_PAIR_SEQ, Tlv.longBytes(claimedPairSeq),
                Protocol.T_EXPIRY, Tlv.longBytes(claimedExpiry)));
        byte[] body = Crypto.aesGcmOpen(kPair, aad, sealed);
        Map<Integer, byte[]> f = Tlv.decode(body);
        PairingTicket t = new PairingTicket(
                Tlv.asUtf8(f.get(Protocol.T_DISPENSER_ID)),
                Tlv.asUtf8(f.get(Protocol.T_TERMINAL_ID)),
                Tlv.asLong(f.get(Protocol.T_PAIR_SEQ)),
                Tlv.asLong(f.get(Protocol.T_NONCE)),
                Tlv.asLong(f.get(Protocol.T_EXPIRY)));
        if (!t.dispenserId.equals(expectedDispenserId)
                || !t.terminalId.equals(claimedTerminalId)
                || t.pairSeq != claimedPairSeq
                || t.expiryEpochSec != claimedExpiry) {
            throw new Crypto.AuthFailureException("ticket header/body binding mismatch");
        }
        if (nowEpochSec > t.expiryEpochSec) {
            throw new Crypto.AuthFailureException("pairing ticket expired");
        }
        return t;
    }
}
