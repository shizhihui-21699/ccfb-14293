package com.atm.protocol;

/**
 * 协议常量：消息类型、TLV 字段标签、版本号、计数器策略。
 */
public final class Protocol {

    public static final byte VERSION = 0x01;

    // ---- 帧类型（总线明文头部携带） ----
    public static final byte TYPE_PAIR = 0x01;        // 配对阶段消息（用 K_PAIR 加密）
    public static final byte TYPE_SECURE = 0x02;      // 正常业务消息（用 K_CHANNEL 加密）
    public static final byte TYPE_RESYNC = 0x03;      // 计数器重同步（仍在 K_CHANNEL 下认证）

    // ---- 应用层命令（密封在安全帧内） ----
    public static final short CMD_HEARTBEAT = 0x0001;
    public static final short CMD_QUERY_STATUS = 0x0002;
    public static final short CMD_DISPENSE = 0x0003;
    public static final short CMD_UPLOAD_OFFLINE_LOG = 0x0004;

    // ---- 配对阶段子命令 ----
    public static final short PAIR_BEGIN = 0x0101;
    public static final short PAIR_ENVELOPE = 0x0102;
    public static final short PAIR_CONFIRM = 0x0103;
    public static final short PAIR_RESULT = 0x0104;

    // ---- TLV 字段标签 ----
    public static final int T_CMD = 0x10;
    public static final int T_TXN_ID = 0x11;
    public static final int T_AMOUNT = 0x12;
    public static final int T_AUTH_TOKEN = 0x13;
    public static final int T_STATUS = 0x14;
    public static final int T_DETAIL = 0x15;
    public static final int T_DISPENSER_ID = 0x16;
    public static final int T_TERMINAL_ID = 0x17;
    public static final int T_PAIR_SEQ = 0x18;
    public static final int T_TICKET = 0x19;
    public static final int T_NONCE = 0x1A;
    public static final int T_ENVELOPE = 0x1B;
    public static final int T_CONFIRM_MAC = 0x1C;
    public static final int T_EXPIRY = 0x1D;
    public static final int T_OFFLINE_INDEX = 0x1E;
    public static final int T_LOG_ENTRY = 0x1F;
    public static final int T_LOG_COUNT = 0x20;
    public static final int T_CASSETTE_INFO = 0x21;
    public static final int T_WINDOW_START = 0x22;
    public static final int T_WINDOW_END = 0x23;
    public static final int T_NONCE_TERMINAL = 0x24;
    public static final int T_NONCE_DISPENSER = 0x25;
    /** 授权令牌类型：1 = 在线单笔令牌；2 = 离线预算令牌。密封在 GCM 帧内，篡改即认证失败。 */
    public static final int T_TOKEN_KIND = 0x26;
    /** 响应帧的目标终端标识（物理总线广播，终端据此过滤非本机响应）。 */
    public static final int T_TARGET = 0x27;
    /** 响应结果码（4 字节 int），与业务状态字段 T_STATUS 区分。 */
    public static final int T_RESULT_CODE = 0x28;
    /** 状态查询返回的钞箱剩余总额（8 字节 long），独立于结果码。 */
    public static final int T_CASH_REMAINING = 0x29;

    public static final byte TOKEN_KIND_ONLINE = 1;
    public static final byte TOKEN_KIND_OFFLINE_BUDGET = 2;

    // ---- 计数器策略 ----
    public static final long COUNTER_REPLAY_WINDOW = 32;
    public static final long RESYNC_THRESHOLD = 256;

    private Protocol() {
    }
}
