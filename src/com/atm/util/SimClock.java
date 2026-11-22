package com.atm.util;

/**
 * 可控时钟：测试中可以任意推进时间，用于验证票据过期等时间相关逻辑。
 * 真实设备上对应 RTC。
 */
public final class SimClock {
    private long epochSeconds;

    public SimClock(long startEpochSeconds) {
        this.epochSeconds = startEpochSeconds;
    }

    public long now() {
        return epochSeconds;
    }

    public void advance(long seconds) {
        if (seconds < 0) {
            throw new IllegalArgumentException("clock cannot go backwards");
        }
        this.epochSeconds += seconds;
    }

    public void set(long epochSeconds) {
        this.epochSeconds = epochSeconds;
    }
}
