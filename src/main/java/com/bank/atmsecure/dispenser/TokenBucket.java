package com.bank.atmsecure.dispenser;

import java.time.Clock;

/** Token bucket, used for verify-budget and handshake-rate limiting on the weak MCU. */
final class TokenBucket {
    private final int capacity;
    private final double refillPerMilli;
    private double tokens;
    private long lastRefillMillis;

    TokenBucket(int capacity, long refillPeriodMillis, Clock clock) {
        this.capacity = capacity;
        this.refillPerMilli = (double) capacity / Math.max(1, refillPeriodMillis);
        this.tokens = capacity;
        this.lastRefillMillis = clock.millis();
    }

    synchronized boolean tryConsume(Clock clock) {
        refill(clock.millis());
        if (tokens >= 1.0) {
            tokens -= 1.0;
            return true;
        }
        return false;
    }

    private void refill(long nowMillis) {
        if (nowMillis > lastRefillMillis) {
            tokens = Math.min(capacity, tokens + (nowMillis - lastRefillMillis) * refillPerMilli);
            lastRefillMillis = nowMillis;
        } else if (nowMillis < lastRefillMillis) {
            // Clock moved backwards. Do not grant free tokens; just re-anchor.
            lastRefillMillis = nowMillis;
        }
    }

    synchronized double available(Clock clock) {
        refill(clock.millis());
        return tokens;
    }
}
