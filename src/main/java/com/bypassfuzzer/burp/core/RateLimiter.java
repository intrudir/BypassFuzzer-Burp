package com.bypassfuzzer.burp.core;

import burp.api.montoya.MontoyaApi;

import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Rate limiter with auto-throttling capabilities.
 * Controls request rate and automatically slows down when throttle status codes are detected.
 */
public class RateLimiter {

    private final MontoyaApi api;
    private final Set<Integer> throttleStatusCodes;
    private final boolean autoThrottleEnabled;

    private volatile int requestsPerSecond;
    private volatile long delayMs;

    private AtomicLong lastRequestTime = new AtomicLong(0);
    private AtomicInteger throttleCount = new AtomicInteger(0);
    private AtomicInteger requestsSinceLastThrottle = new AtomicInteger(0);

    // Auto-throttle parameters
    private static final int THROTTLE_DETECTION_WINDOW = 5; // Detect after N throttle responses
    private static final double THROTTLE_SLOWDOWN_FACTOR = 0.5; // Reduce speed by 50%
    private static final int MIN_DELAY_MS = 100; // Minimum 100ms between requests when throttled
    private static final int RESET_AFTER_REQUESTS = 50; // Reset throttle counter after N successful requests

    public RateLimiter(MontoyaApi api, int requestsPerSecond, Set<Integer> throttleStatusCodes, boolean autoThrottleEnabled) {
        this.api = api;
        this.requestsPerSecond = requestsPerSecond;
        this.throttleStatusCodes = throttleStatusCodes;
        this.autoThrottleEnabled = autoThrottleEnabled;
        this.delayMs = calculateDelayMs(requestsPerSecond);
    }

    /**
     * Wait before sending the next request according to rate limit.
     */
    public void waitBeforeRequest() {
        if (delayMs <= 0) {
            return; // No rate limiting
        }

        long currentTime = System.currentTimeMillis();
        long timeSinceLastRequest = currentTime - lastRequestTime.get();

        if (timeSinceLastRequest < delayMs) {
            long sleepTime = delayMs - timeSinceLastRequest;
            try {
                Thread.sleep(sleepTime);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        lastRequestTime.set(System.currentTimeMillis());
    }

    /**
     * Report a response status code for auto-throttling.
     * @param statusCode The HTTP status code received
     */
    public void reportResponse(int statusCode) {
        if (!autoThrottleEnabled || throttleStatusCodes.isEmpty()) {
            return;
        }

        if (throttleStatusCodes.contains(statusCode)) {
            int count = throttleCount.incrementAndGet();
            requestsSinceLastThrottle.set(0);

            // After multiple throttle responses, slow down
            if (count >= THROTTLE_DETECTION_WINDOW) {
                applyAutoThrottle();
                throttleCount.set(0); // Reset counter after applying throttle
            }
        } else {
            // Successful request
            int successCount = requestsSinceLastThrottle.incrementAndGet();

            // Reset throttle counter after many successful requests
            if (successCount >= RESET_AFTER_REQUESTS) {
                if (throttleCount.get() > 0) {
                    throttleCount.set(0);
                }
            }
        }
    }

    /**
     * Apply auto-throttling by increasing delay.
     */
    private void applyAutoThrottle() {
        long newDelayMs;

        if (delayMs <= 0) {
            // No current limit, start with minimum delay
            newDelayMs = MIN_DELAY_MS;
        } else {
            // Increase delay by slowdown factor
            newDelayMs = (long) (delayMs / THROTTLE_SLOWDOWN_FACTOR);
        }

        // Update delay
        delayMs = newDelayMs;

        // Calculate equivalent requests per second
        int newRps = (int) (1000.0 / newDelayMs);
        requestsPerSecond = Math.max(1, newRps);

        try {
            api.logging().logToOutput(
                String.format("⚠ Auto-throttle activated: Detected rate limiting (status codes: %s). " +
                    "Reducing speed to ~%d req/s (%d ms delay between requests).",
                    throttleStatusCodes, requestsPerSecond, delayMs)
            );
        } catch (Exception e) {
            // Ignore logging errors
        }
    }

    /**
     * Update the rate limit setting.
     * @param requestsPerSecond New requests per second (0 = unlimited)
     */
    public void updateRateLimit(int requestsPerSecond) {
        this.requestsPerSecond = requestsPerSecond;
        this.delayMs = calculateDelayMs(requestsPerSecond);
    }

    /**
     * Calculate delay in milliseconds from requests per second.
     */
    private long calculateDelayMs(int requestsPerSecond) {
        if (requestsPerSecond <= 0) {
            return 0; // No limit
        }
        return 1000L / requestsPerSecond;
    }

    /**
     * Get current effective requests per second.
     */
    public int getCurrentRequestsPerSecond() {
        return requestsPerSecond;
    }

    /**
     * Get current delay in milliseconds.
     */
    public long getCurrentDelayMs() {
        return delayMs;
    }
}
