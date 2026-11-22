package com.atm.protocol;

import java.util.HashMap;
import java.util.Map;

/**
 * 出钞模块返回给终端的状态码。任何拒绝路径都使用明确的拒绝码，
 * 测试通过拒绝码区分“被安全机制拦截”与“硬件业务原因失败”。
 */
public enum ResultCode {
    OK(0),
    NOT_PAIRED(1),
    AUTH_FAILED(2),             // GCM 校验失败 / 帧来源不可信
    REPLAY_DETECTED(3),         // 计数器回退或 txnId 重复
    PAIR_MODE_REQUIRED(4),      // 设备不在物理配对模式
    TICKET_INVALID(5),          // KMS 票据校验失败
    TICKET_EXPIRED(6),
    PAIR_SEQ_STALE(7),          // 配对序号不是严格递增
    DEVICE_MISMATCH(8),         // 票据中的设备标识与实际不符
    COMMAND_UNKNOWN(9),
    AUTH_TOKEN_INVALID(10),     // 主机授权令牌无效
    AUTH_TOKEN_EXPIRED(11),
    TXN_ALREADY_EXECUTED(12),   // 同一 txnId 的出钞已执行，幂等返回
    AMOUNT_MISMATCH(13),        // 命令金额与授权令牌金额不一致
    OFFLINE_INDEX_REUSED(14),
    OFFLINE_QUOTA_EXCEEDED(15),
    OFFLINE_BUDGET_EXHAUSTED(16),
    LOG_TAMPERED(17),
    RESYNC_REJECTED(18),
    HARDWARE_FAULT(19),
    INSUFFICIENT_CASH(20);

    private static final Map<Integer, ResultCode> BY_CODE = new HashMap<>();

    static {
        for (ResultCode c : values()) {
            BY_CODE.put(c.code, c);
        }
    }

    private final int code;

    ResultCode(int code) {
        this.code = code;
    }

    public int code() {
        return code;
    }

    public static ResultCode byCode(int code) {
        ResultCode c = BY_CODE.get(code);
        if (c == null) {
            throw new IllegalArgumentException("unknown result code: " + code);
        }
        return c;
    }

    public boolean isSecurityRejection() {
        return switch (this) {
            case AUTH_FAILED, REPLAY_DETECTED, PAIR_MODE_REQUIRED, TICKET_INVALID,
                 TICKET_EXPIRED, PAIR_SEQ_STALE, DEVICE_MISMATCH, AUTH_TOKEN_INVALID,
                 AUTH_TOKEN_EXPIRED, OFFLINE_INDEX_REUSED, OFFLINE_QUOTA_EXCEEDED,
                 OFFLINE_BUDGET_EXHAUSTED, LOG_TAMPERED, RESYNC_REJECTED -> true;
            default -> false;
        };
    }
}
