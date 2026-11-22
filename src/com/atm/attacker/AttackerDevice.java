package com.atm.attacker;

import com.atm.bus.BusDevice;
import com.atm.bus.BusFrame;
import com.atm.bus.PhysicalBus;
import com.atm.crypto.Crypto;
import com.atm.protocol.Protocol;
import com.atm.protocol.Tlv;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 攻击者的小电脑：物理接入出钞模块数据线的任意设备。
 * <p>
 * 它拥有真实攻击面允许的全部能力，但<b>不持有任何合法密钥</b>：
 * <ul>
 *   <li>嗅探总线上的全部帧；</li>
 *   <li>注入任意手工构造的帧（伪造头部/计数器/载荷）；</li>
 *   <li>重放历史帧、篡改字节后重发；</li>
 *   <li>尝试构造裸出钞命令、配对消息、重同步请求；</li>
 *   <li>冒充任意 sourceId。</li>
 * </ul>
 */
public final class AttackerDevice implements BusDevice {

    private final String attackerId;
    private final List<BusFrame> received = new ArrayList<>();

    public AttackerDevice(String attackerId) {
        this.attackerId = attackerId;
    }

    @Override
    public String deviceId() {
        return attackerId;
    }

    @Override
    public void onFrame(BusFrame frame, PhysicalBus bus) {
        received.add(frame);
    }

    public List<BusFrame> observed() {
        return new ArrayList<>(received);
    }

    /** 直接注入一帧原始字节（伪造帧能力）。 */
    public void injectRaw(PhysicalBus bus, BusFrame frame) {
        bus.inject(frame);
    }

    /**
     * 攻击 1：无密钥裸出钞——复刻原始漏洞。手工拼一条出钞命令，
     * 头部冒充合法终端，但没有任何 GCM 密封。
     */
    public void rawDispenseCommand(PhysicalBus bus, String spoofedSource,
                                   String txnId, long amount) {
        Map<Integer, byte[]> cmd = Tlv.builder();
        cmd.put(Protocol.T_CMD, Tlv.intBytes(Protocol.CMD_DISPENSE));
        cmd.put(Protocol.T_TXN_ID, Tlv.utf8(txnId));
        cmd.put(Protocol.T_AMOUNT, Tlv.longBytes(amount));
        byte[] plaintext = Tlv.encode(cmd);
        // 攻击者没有 K_CHANNEL，只能发明文/随机字节
        BusFrame frame = new BusFrame(Protocol.TYPE_SECURE, spoofedSource, 0, plaintext);
        bus.inject(frame);
    }

    /** 攻击 2：用随机字节当密封载荷，试探解析器崩溃或状态污染。 */
    public void garbageSecureFrame(PhysicalBus bus, String spoofedSource, long counter) {
        bus.inject(new BusFrame(Protocol.TYPE_SECURE, spoofedSource, counter,
                Crypto.randomBytes(64)));
    }

    /** 攻击 3：重放嗅探到的历史帧（原样再发一次）。 */
    public void replay(PhysicalBus bus, BusFrame historical) {
        bus.inject(new BusFrame(historical.type, historical.sourceId,
                historical.counter, historical.sealedPayload.clone()));
    }

    /** 攻击 4：篡改密封载荷字节后重发（GCM tag 必然失效）。 */
    public void tamperAndReplay(PhysicalBus bus, BusFrame historical, int byteOffset) {
        byte[] payload = historical.sealedPayload.clone();
        if (byteOffset < payload.length) {
            payload[byteOffset] ^= 0x01;
        }
        bus.inject(new BusFrame(historical.type, historical.sourceId,
                historical.counter, payload));
    }

    /** 攻击 5：篡改明文头部（sourceId / 计数器）后重发——AAD 失配。 */
    public void tamperHeaderAndReplay(PhysicalBus bus, BusFrame historical,
                                      String newSource, long newCounter) {
        bus.inject(new BusFrame(historical.type, newSource, newCounter,
                historical.sealedPayload.clone()));
    }

    /** 攻击 6：伪造配对消息（无 K_PAIR，载荷只能是垃圾）。 */
    public void fakePairingBegin(PhysicalBus bus, String dispenserId,
                                 String claimedTerminal, long claimedSeq) {
        Map<Integer, byte[]> cmd = Tlv.builder();
        cmd.put(Protocol.T_CMD, Tlv.intBytes(Protocol.PAIR_BEGIN));
        cmd.put(Protocol.T_TERMINAL_ID, Tlv.utf8(claimedTerminal));
        cmd.put(Protocol.T_DISPENSER_ID, Tlv.utf8(dispenserId));
        cmd.put(Protocol.T_PAIR_SEQ, Tlv.longBytes(claimedSeq));
        cmd.put(Protocol.T_TICKET, Crypto.randomBytes(48));
        bus.inject(new BusFrame(Protocol.TYPE_PAIR, attackerId, 0, Tlv.encode(cmd)));
    }

    /** 攻击 7：伪造重同步，试图把接收计数器推高造成合法帧被拒。 */
    public void fakeResync(PhysicalBus bus, String spoofedSource, long hugeCounter) {
        Map<Integer, byte[]> cmd = Tlv.builder();
        cmd.put(Protocol.T_CMD, Tlv.intBytes(Protocol.CMD_HEARTBEAT));
        cmd.put(Protocol.T_NONCE, Tlv.longBytes(hugeCounter));
        bus.inject(new BusFrame(Protocol.TYPE_RESYNC, spoofedSource, hugeCounter,
                Tlv.encode(cmd)));
    }

    /** 攻击 8：重放旧配对票据帧（从历史流量中抓取 TYPE_PAIR）。 */
    public void replayOldPairingFrame(PhysicalBus bus, List<BusFrame> history) {
        for (BusFrame f : history) {
            if (f.type == Protocol.TYPE_PAIR) {
                bus.inject(new BusFrame(f.type, f.sourceId, f.counter, f.sealedPayload.clone()));
                return;
            }
        }
    }

    /** 攻击 9：大量垃圾帧泛洪，验证安全状态不被扰乱（DoS 韧性）。 */
    public void flood(PhysicalBus bus, String spoofedSource, int count) {
        for (int i = 0; i < count; i++) {
            garbageSecureFrame(bus, spoofedSource, i);
        }
    }
}
