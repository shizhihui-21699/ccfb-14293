package com.atm.tests;

import com.atm.bus.BusFrame;
import com.atm.crypto.Crypto;
import com.atm.protocol.Protocol;
import com.atm.protocol.Tlv;
import com.atm.security.SecureChannel;

import java.util.List;
import java.util.Map;

/**
 * 密码原语与安全通道的单元测试：HKDF 域隔离、GCM 篡改检测、计数器重放窗口。
 */
public final class ProtocolCryptoTest extends AtmTest {

    public static List<AtmTest> suite() {
        return List.of(
                new ProtocolCryptoTest("hkdf 不同标签派生出不同密钥", () -> new ProtocolCryptoTest().tHkdfLabelSeparation()),
                new ProtocolCryptoTest("GCM 篡改密文即认证失败", () -> new ProtocolCryptoTest().tGcmTamper()),
                new ProtocolCryptoTest("GCM 篡改 AAD 即认证失败", () -> new ProtocolCryptoTest().tGcmAadTamper()),
                new ProtocolCryptoTest("错误密钥解密失败", () -> new ProtocolCryptoTest().tGcmWrongKey()),
                new ProtocolCryptoTest("安全通道重放同一计数器被拒", () -> new ProtocolCryptoTest().tReplayCounter()),
                new ProtocolCryptoTest("乱序帧在窗口内被接受", () -> new ProtocolCryptoTest().tReorderWindow()),
                new ProtocolCryptoTest("过旧帧超出窗口被拒", () -> new ProtocolCryptoTest().tOutOfWindow()),
                new ProtocolCryptoTest("认证失败不推进接收状态", () -> new ProtocolCryptoTest().tAuthFailureNoStateChange()),
                new ProtocolCryptoTest("重同步只允许有限前跳", () -> new ProtocolCryptoTest().tResyncBounded()),
                new ProtocolCryptoTest("TLV 往返编解码一致", () -> new ProtocolCryptoTest().tTlvRoundTrip()),
                new ProtocolCryptoTest("总线帧序列化往返一致", () -> new ProtocolCryptoTest().tFrameRoundTrip()));
    }

    private final Runnable body;

    private ProtocolCryptoTest() {
        this.overrideName = null;
        this.body = null;
    }

    private ProtocolCryptoTest(String name, Runnable body) {
        this.body = body;
        this.overrideName = name;
    }

    private final String overrideName;

    @Override
    public String name() {
        return overrideName;
    }

    @Override
    public void run() {
        body.run();
    }

    private void tHkdfLabelSeparation() {
        byte[] kdk = Crypto.randomBytes(32);
        byte[] a = Crypto.hkdf(kdk, com.atm.crypto.KeyLabel.CHANNEL, 32);
        byte[] b = Crypto.hkdf(kdk, com.atm.crypto.KeyLabel.AUTH, 32);
        check(!Crypto.constantTimeEquals(a, b), "different labels must derive different keys");
        byte[] a2 = Crypto.hkdf(kdk, com.atm.crypto.KeyLabel.CHANNEL, 32);
        check(Crypto.constantTimeEquals(a, a2), "same label must derive deterministically");
    }

    private void tGcmTamper() {
        byte[] key = Crypto.randomBytes(32);
        byte[] sealed = Crypto.aesGcmSeal(key, null, Tlv.utf8("payload"));
        sealed[sealed.length - 1] ^= 1;
        expectAuthFailure(() -> Crypto.aesGcmOpen(key, null, sealed));
    }

    private void tGcmAadTamper() {
        byte[] key = Crypto.randomBytes(32);
        byte[] aad = Tlv.utf8("header-binding");
        byte[] sealed = Crypto.aesGcmSeal(key, aad, Tlv.utf8("payload"));
        byte[] badAad = Tlv.utf8("header-bindinh");
        expectAuthFailure(() -> Crypto.aesGcmOpen(key, badAad, sealed));
    }

    private void tGcmWrongKey() {
        byte[] sealed = Crypto.aesGcmSeal(Crypto.randomBytes(32), null, Tlv.utf8("x"));
        expectAuthFailure(() -> Crypto.aesGcmOpen(Crypto.randomBytes(32), null, sealed));
    }

    private void tReplayCounter() {
        // 双方共享同一密钥
        byte[] key = Crypto.randomBytes(32);
        SecureChannel sender = new SecureChannel(key);
        SecureChannel receiver = new SecureChannel(key);
        byte[] p0 = sender.seal(Protocol.TYPE_SECURE, "a", Tlv.utf8("m0"));
        long c0 = sender.sendCounter() - 1;
        receiver.open(new BusFrame(Protocol.TYPE_SECURE, "a", c0, p0));
        expectReplay(() -> receiver.open(new BusFrame(Protocol.TYPE_SECURE, "a", c0, p0.clone())));
    }

    private void tReorderWindow() {
        byte[] key = Crypto.randomBytes(32);
        SecureChannel sender = new SecureChannel(key);
        SecureChannel receiver = new SecureChannel(key);
        byte[][] frames = new byte[5][];
        long[] counters = new long[5];
        for (int i = 0; i < 5; i++) {
            frames[i] = sender.seal(Protocol.TYPE_SECURE, "a", Tlv.utf8("m" + i));
            counters[i] = sender.sendCounter() - 1;
        }
        // 乱序交付：0,2,1,4,3
        int[] order = {0, 2, 1, 4, 3};
        for (int idx : order) {
            receiver.open(new BusFrame(Protocol.TYPE_SECURE, "a", counters[idx], frames[idx]));
        }
        check(true, "in-window reorder accepted");
    }

    private void tOutOfWindow() {
        byte[] key = Crypto.randomBytes(32);
        SecureChannel sender = new SecureChannel(key);
        SecureChannel receiver = new SecureChannel(key);
        byte[] first = sender.seal(Protocol.TYPE_SECURE, "a", Tlv.utf8("m0"));
        long c0 = sender.sendCounter() - 1;
        receiver.open(new BusFrame(Protocol.TYPE_SECURE, "a", c0, first));
        // 推进到窗口之外
        for (long c = 1; c <= Protocol.COUNTER_REPLAY_WINDOW + 5; c++) {
            byte[] f = sender.seal(Protocol.TYPE_SECURE, "a", Tlv.utf8("m" + c));
            receiver.open(new BusFrame(Protocol.TYPE_SECURE, "a", sender.sendCounter() - 1, f));
        }
        expectReplay(() -> receiver.open(new BusFrame(Protocol.TYPE_SECURE, "a", c0, first.clone())));
    }

    private void tAuthFailureNoStateChange() {
        byte[] key = Crypto.randomBytes(32);
        SecureChannel sender = new SecureChannel(key);
        SecureChannel receiver = new SecureChannel(key);
        byte[] good = sender.seal(Protocol.TYPE_SECURE, "a", Tlv.utf8("ok"));
        long goodCtr = sender.sendCounter() - 1;
        // 垃圾帧：GCM 失败，状态不得变化
        expectAuthFailure(() -> receiver.open(
                new BusFrame(Protocol.TYPE_SECURE, "a", 999, Crypto.randomBytes(40))));
        long before = receiver.receiveCounter();
        expectAuthFailure(() -> receiver.open(
                new BusFrame(Protocol.TYPE_SECURE, "a", 12345, Crypto.randomBytes(40))));
        checkEq(receiver.receiveCounter(), before, "receiver state unchanged after auth failures");
        // 合法帧依旧可用
        receiver.open(new BusFrame(Protocol.TYPE_SECURE, "a", goodCtr, good));
        checkEq(receiver.receiveCounter(), goodCtr, "legit frame still accepted");
    }

    private void tResyncBounded() {
        byte[] key = Crypto.randomBytes(32);
        SecureChannel ch = new SecureChannel(key);
        byte[] f0 = ch.seal(Protocol.TYPE_SECURE, "a", Tlv.utf8("x"));
        ch.open(new BusFrame(Protocol.TYPE_SECURE, "a", 0, f0));
        ch.resync(10);
        expectReplay(() -> ch.resync(10));          // 不前跳
        expectReplay(() -> ch.resync(10_000));      // 跳太远
    }

    private void tTlvRoundTrip() {
        Map<Integer, byte[]> m = Tlv.builder();
        m.put(1, Tlv.utf8("hello"));
        m.put(2, Tlv.longBytes(99_999_999_999L));
        m.put(3, new byte[] {0, 1, 2, 3});
        Map<Integer, byte[]> back = Tlv.decode(Tlv.encode(m));
        checkEq(Tlv.asUtf8(back.get(1)), "hello", "string field");
        checkEq(Tlv.asLong(back.get(2)), 99_999_999_999L, "long field");
    }

    private void tFrameRoundTrip() {
        BusFrame f = new BusFrame(Protocol.TYPE_SECURE, "dev-7", 4242, Crypto.randomBytes(50));
        BusFrame parsed = BusFrame.parse(f.serialize());
        checkEq(parsed.type, f.type, "type");
        checkEq(parsed.sourceId, f.sourceId, "source");
        checkEq(parsed.counter, f.counter, "counter");
        check(Crypto.constantTimeEquals(parsed.sealedPayload, f.sealedPayload), "payload");
        check(Crypto.constantTimeEquals(parsed.aad(), f.aad()), "aad stable");
    }

    private void expectAuthFailure(Runnable r) {
        try {
            r.run();
            fail("expected AuthFailureException");
        } catch (Crypto.AuthFailureException expected) {
            checks++;
        }
    }

    private void expectReplay(Runnable r) {
        try {
            r.run();
            fail("expected ReplayException");
        } catch (SecureChannel.ReplayException expected) {
            checks++;
        }
    }
}
