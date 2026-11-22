package com.atm.bus;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 模拟出钞模块与业务电脑之间的物理数据总线（如 USB / RS-485）。
 * <p>
 * 关键安全假设：总线上没有任何物理层访问控制。任何接入者都可以：
 * <ul>
 *   <li>发送任意伪造帧（{@link #inject}）</li>
 *   <li>收到全部流量的副本（窃听，{@link #sniffedFrames()}）</li>
 *   <li>注册为 MITM 拦截/篡改/丢弃转发的帧（{@link #setMitm}）</li>
 * </ul>
 * 因此所有安全保证必须来自帧内部的密码学材料，而不是“谁在线上”。
 */
public final class PhysicalBus {

    private final List<BusDevice> devices = new CopyOnWriteArrayList<>();
    private final List<BusFrame> sniffed = new ArrayList<>();
    private volatile Mitm mitm;
    private long totalFrames;
    private long droppedByMitm;

    public void attach(BusDevice device) {
        devices.add(device);
    }

    public void detach(BusDevice device) {
        devices.remove(device);
    }

    public void setMitm(Mitm mitm) {
        this.mitm = mitm;
    }

    /**
     * 正常发送：先经过可选 MITM，再广播给除发送者外的所有设备。
     * 每一份发出的帧都会进入嗅探记录（攻击者视角等价于物理探针）。
     */
    public synchronized void send(BusDevice sender, BusFrame frame) {
        totalFrames++;
        sniffed.add(frame);
        Mitm m = this.mitm;
        if (m != null) {
            BusFrame replaced = m.intercept(frame);
            if (replaced == null) {
                droppedByMitm++;
                return;
            }
            frame = replaced;
        }
        for (BusDevice d : devices) {
            if (d != sender) {
                deliver(d, frame);
            }
        }
    }

    /**
     * 攻击者注入：不经过 MITM（攻击者本身就是主动接入者），直接广播，
     * 同样会被其他所有接入者（包括合法设备）收到。
     */
    public synchronized void inject(BusFrame frame) {
        totalFrames++;
        sniffed.add(frame);
        for (BusDevice d : devices) {
            deliver(d, frame);
        }
    }

    /**
     * 投递深度护栏：物理总线在 send() 调用栈内同步投递，若某设备在 onFrame
     * 处理中又回发帧，可能形成跨设备无限递归。超过阈值即中止该次投递，
     * 保护弱算力设备的栈空间。正常协议的投递深度为 2（发送→接收→响应）。
     */
    private static final int MAX_DELIVERY_DEPTH = 16;
    private static final ThreadLocal<Integer> DEPTH = ThreadLocal.withInitial(() -> 0);

    private void deliver(BusDevice d, BusFrame frame) {
        int depth = DEPTH.get() + 1;
        if (depth > MAX_DELIVERY_DEPTH) {
            System.err.println("[bus] delivery depth exceeded " + MAX_DELIVERY_DEPTH
                    + " — dropping frame to device " + d.deviceId()
                    + " (possible on-frame send loop)");
            return;
        }
        DEPTH.set(depth);
        try {
            d.onFrame(frame, this);
        } catch (Throwable e) {
            // 单个设备处理异常不影响总线与其他设备
            System.err.println("[bus] device " + d.deviceId() + " threw on frame: " + e);
        } finally {
            DEPTH.set(depth - 1);
        }
    }

    /** 攻击者视角：线缆上出现过的每一帧的完整副本。 */
    public synchronized List<BusFrame> sniffedFrames() {
        return BusFrame.deepCopyFrames(sniffed);
    }

    public synchronized void clearSniffer() {
        sniffed.clear();
    }

    public long totalFrames() {
        return totalFrames;
    }

    public long droppedByMitm() {
        return droppedByMitm;
    }

    /**
     * 中间人钩子：返回替换后的帧，返回 null 表示丢弃该帧。
     * 注意：篡改 GCM 密封帧的任何字节都会在接收端触发 AUTH_FAILED。
     */
    @FunctionalInterface
    public interface Mitm {
        BusFrame intercept(BusFrame original);
    }
}
