package com.atm.security;

import com.atm.bus.BusFrame;
import com.atm.crypto.Crypto;
import com.atm.protocol.Protocol;

import java.util.BitSet;

/**
 * 带防重放计数器的 GCM 安全通道。
 * <p>
 * 发送端维护单调递增 sendCounter；接收端维护“已接受最大计数器 + 位图窗口”。
 * 关键安全性质：<b>只有 GCM 认证通过的帧才会推进接收状态</b>——
 * 伪造帧/篡改帧在 {@code open} 阶段即抛异常，计数器与位图完全不变，
 * 因此攻击者无法通过垃圾帧扰乱窗口把合法帧挤出接受范围。
 */
public final class SecureChannel {

    private final byte[] key;
    private long sendCounter;
    private long rcvCounter = -1;
    private final BitSet window = new BitSet((int) Protocol.COUNTER_REPLAY_WINDOW);

    public SecureChannel(byte[] key) {
        this(key, 0);
    }

    public SecureChannel(byte[] key, long initialSendCounter) {
        this.key = key.clone();
        this.sendCounter = initialSendCounter;
    }

    public long sendCounter() {
        return sendCounter;
    }

    public long receiveCounter() {
        return rcvCounter;
    }

    /** 密封一帧并占用一个发送序号。 */
    public byte[] seal(byte type, String sourceId, byte[] plaintext) {
        long counter = sendCounter++;
        byte[] aad = BusFrame.buildAad(type, sourceId, counter);
        return Crypto.aesGcmSeal(key, aad, plaintext);
    }

    /** 仅密封、不推进序号（重发同一帧时使用，保持幂等）。 */
    public byte[] sealAtCounter(byte type, String sourceId, long counter, byte[] plaintext) {
        byte[] aad = BusFrame.buildAad(type, sourceId, counter);
        return Crypto.aesGcmSeal(key, aad, plaintext);
    }

    public long nextCounter() {
        return sendCounter;
    }

    public void advanceSendCounter() {
        sendCounter++;
    }

    /**
     * 验证并解密。任何失败都抛出异常且不改变本对象状态。
     *
     * @throws Crypto.AuthFailureException GCM 标签错误（伪造/篡改/错误密钥）
     * @throws ReplayException            认证通过但计数器落在重放窗口内
     */
    public byte[] open(BusFrame frame) {
        byte[] aad = frame.aad();
        byte[] plaintext = Crypto.aesGcmOpen(key, aad, frame.sealedPayload); // 失败即抛，状态不变
        acceptCounter(frame.counter);
        return plaintext;
    }

    private void acceptCounter(long counter) {
        if (rcvCounter < 0) {
            rcvCounter = counter;
            window.set(0);
            return;
        }
        long w = Protocol.COUNTER_REPLAY_WINDOW;
        if (counter > rcvCounter) {
            long gap = counter - rcvCounter;
            if (gap >= w) {
                window.clear();
            } else {
                // 位图随窗口前移
                BitSet shifted = new BitSet((int) w);
                for (int i = window.nextSetBit(0); i >= 0; i = window.nextSetBit(i + 1)) {
                    int ni = i + (int) gap;
                    if (ni < w) {
                        shifted.set(ni);
                    }
                }
                window.clear();
                window.or(shifted);
            }
            rcvCounter = counter;
            window.set(0);
        } else {
            long diff = rcvCounter - counter;
            if (diff >= w) {
                throw new ReplayException("counter too old: " + counter + " < window base " + (rcvCounter - w + 1));
            }
            int idx = (int) diff;
            if (window.get(idx)) {
                throw new ReplayException("replayed counter: " + counter);
            }
            window.set(idx);
        }
    }

    /**
     * 重同步：帧本身仍然必须通过 GCM 认证。仅允许序号向前有限跳跃，
     * 防止攻击者把接收端序号推到极端值造成拒绝服务。
     */
    public void resync(long proposedCounter) {
        if (rcvCounter < 0) {
            rcvCounter = proposedCounter;
            window.set(0);
            return;
        }
        if (proposedCounter <= rcvCounter) {
            throw new ReplayException("resync counter not ahead: " + proposedCounter);
        }
        if (proposedCounter - rcvCounter > Protocol.RESYNC_THRESHOLD) {
            throw new ReplayException("resync jump too large");
        }
        rcvCounter = proposedCounter;
        window.clear();
        window.set(0);
    }

    /**
     * 必须是静态嵌套类：非静态内部类会持有外部 SecureChannel 引用，
     * 异常在堆栈格式化时可能触发外部类的递归 toString 导致栈溢出。
     */
    public static class ReplayException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public ReplayException(String message) {
            super(message);
        }
    }
}
