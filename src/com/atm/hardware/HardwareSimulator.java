package com.atm.hardware;

import java.util.ArrayList;
import java.util.List;

/**
 * 出钞机械硬件模拟：钞箱、面额、出钞计数。
 * 指令层通过 {@link #dispense} 驱动它——测试用本类的实际出钞计数作为
 * “攻击是否真的吐出钱”的唯一判定依据。
 */
public final class HardwareSimulator {

    /** 单个钞箱。 */
    public static final class Cassette {
        public final String id;
        public final int denominationMinor;
        public int notes;

        public Cassette(String id, int denominationMinor, int notes) {
            this.id = id;
            this.denominationMinor = denominationMinor;
            this.notes = notes;
        }
    }

    private final List<Cassette> cassettes = new ArrayList<>();
    private long totalDispensedMinor;
    private long dispenseOperations;
    private boolean jammed;

    public void addCassette(String id, int denomination, int notes) {
        cassettes.add(new Cassette(id, denomination, notes));
    }

    /** 测试专用：模拟卡钞。 */
    public void setJam(boolean jammed) {
        this.jammed = jammed;
    }

    /**
     * 执行出钞。简单贪心配钞。只有真实机械动作成功才计数。
     *
     * @return 成功吐出的金额（分）；硬件失败返回 -1
     */
    public synchronized long dispense(long amountMinor) {
        if (jammed) {
            return -1;
        }
        long remaining = amountMinor;
        List<Cassette> sorted = new ArrayList<>(cassettes);
        sorted.sort((a, b) -> Integer.compare(b.denominationMinor, a.denominationMinor));

        // 先试算，保证不会出现“吐了一半”的部分出钞
        int[][] plan = new int[sorted.size()][1];
        for (int i = 0; i < sorted.size(); i++) {
            Cassette c = sorted.get(i);
            int need = (int) (remaining / c.denominationMinor);
            int take = Math.min(need, c.notes);
            plan[i] = new int[] {take};
            remaining -= (long) take * c.denominationMinor;
        }
        if (remaining != 0) {
            return -1; // 无法精确配钞，机械不动
        }
        for (int i = 0; i < sorted.size(); i++) {
            sorted.get(i).notes -= plan[i][0];
        }
        totalDispensedMinor += amountMinor;
        dispenseOperations++;
        return amountMinor;
    }

    public synchronized long totalDispensed() {
        return totalDispensedMinor;
    }

    public synchronized long dispenseOperations() {
        return dispenseOperations;
    }

    public synchronized long cashRemaining() {
        long sum = 0;
        for (Cassette c : cassettes) {
            sum += (long) c.notes * c.denominationMinor;
        }
        return sum;
    }

    public synchronized List<String> cassetteSnapshot() {
        List<String> snap = new ArrayList<>();
        for (Cassette c : cassettes) {
            snap.add(c.id + ":" + c.denominationMinor + "x" + c.notes);
        }
        return snap;
    }
}
