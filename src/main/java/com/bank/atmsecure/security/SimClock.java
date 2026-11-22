package com.bank.atmsecure.security;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Test-controllable clock. The dispenser has a weak but tamper-monotonic RTC; tests need to move it
 * forward without sleeping, and to check that time cannot be moved backwards behind our back.
 */
public final class SimClock extends Clock {
    private final AtomicLong millis;

    public SimClock(Instant start) {
        this.millis = new AtomicLong(start.toEpochMilli());
    }

    public static SimClock at(String isoInstant) {
        return new SimClock(Instant.parse(isoInstant));
    }

    @Override
    public long millis() {
        return millis.get();
    }

    public void setMillis(long value) {
        millis.set(value);
    }

    public void advanceMillis(long delta) {
        millis.addAndGet(delta);
    }

    @Override
    public Instant instant() {
        return Instant.ofEpochMilli(millis.get());
    }

    @Override
    public ZoneOffset getZone() {
        return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(java.time.ZoneId zone) {
        return this;
    }
}
