package com.cyberincident.security;

import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory IP and Username Rate Limiter with Exponential Delay / Temporary Lockout.
 * Protects against credential stuffing and brute force dictionary attacks.
 */
public class LoginRateLimiter {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCKOUT_DURATION_MS = 15 * 60 * 1000L; // 15 minutes lockout

    private static class AttemptRecord {
        int failures;
        long lockedUntil;
        long lastAttemptTime;

        AttemptRecord() {
            this.failures = 1;
            this.lockedUntil = 0;
            this.lastAttemptTime = System.currentTimeMillis();
        }
    }

    private static final ConcurrentHashMap<String, AttemptRecord> ATTEMPTS = new ConcurrentHashMap<>();

    /**
     * Checks if the given key (IP or username) is currently locked out.
     * @return remaining lockout seconds, or 0 if allowed.
     */
    public static long isLocked(String key) {
        if (key == null || key.trim().isEmpty()) return 0;
        AttemptRecord record = ATTEMPTS.get(key.trim().toLowerCase());
        if (record == null) return 0;

        long now = System.currentTimeMillis();
        if (record.lockedUntil > now) {
            return (record.lockedUntil - now) / 1000L + 1;
        }

        // Lockout expired, reset failures if lock duration has elapsed
        if (record.lockedUntil > 0 && record.lockedUntil <= now) {
            ATTEMPTS.remove(key.trim().toLowerCase());
        }
        return 0;
    }

    /**
     * Records a failed authentication attempt.
     */
    public static void recordFailure(String key) {
        if (key == null || key.trim().isEmpty()) return;
        String cleanKey = key.trim().toLowerCase();
        long now = System.currentTimeMillis();

        ATTEMPTS.compute(cleanKey, (k, record) -> {
            if (record == null || (now - record.lastAttemptTime > LOCKOUT_DURATION_MS)) {
                return new AttemptRecord();
            }
            record.failures++;
            record.lastAttemptTime = now;
            if (record.failures >= MAX_FAILED_ATTEMPTS) {
                record.lockedUntil = now + LOCKOUT_DURATION_MS;
            }
            return record;
        });
    }

    /**
     * Resets failure counter upon successful login.
     */
    public static void recordSuccess(String key) {
        if (key != null) {
            ATTEMPTS.remove(key.trim().toLowerCase());
        }
    }
}
