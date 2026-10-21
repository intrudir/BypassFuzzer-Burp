package com.bypassfuzzer.core.throttle;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.LongSupplier;

/**
 * Adaptive per-host request pacing that discovers a server's rate-limit ceiling and rides just
 * under it.
 *
 * <p>The controller meters admission with a token bucket whose refill {@code rate} (requests per
 * second) is the single adapted variable. It follows an AIMD (additive-increase /
 * multiplicative-decrease) discipline, the same congestion-control principle TCP uses to run a link
 * at capacity:</p>
 *
 * <ul>
 *   <li><b>Slow start</b> &mdash; before any throttle is seen, the rate grows geometrically each
 *       adjustment window so the ceiling is found quickly.</li>
 *   <li><b>Steady</b> &mdash; once a throttle (429/503 or a {@code Retry-After}) reveals the ceiling,
 *       the rate is increased additively with a step that shrinks as it approaches the last known
 *       ceiling (a gentle, CUBIC-like approach) and creeps only slowly above it. Each throttle
 *       multiplicatively decreases the rate by a gentle factor, keeping the sawtooth shallow so the
 *       average throughput sits just below the true limit.</li>
 * </ul>
 *
 * <p>A {@code Retry-After} response is honored as a hard pause. A cluster of in-flight throttles is
 * collapsed into a single "loss event" via a monotonically increasing {@code generation}: callers
 * capture the generation at {@link #acquire()} and hand it back to
 * {@link #report(int, String, long)} so responses issued before a rate change cannot penalize (or
 * inflate) the new rate.</p>
 *
 * <p>The class is deliberately free of any Burp/Montoya dependency and takes primitive feedback so
 * it can be unit-tested on a virtual clock and reused by the standalone live-tuning harness without
 * drift.</p>
 */
public final class AdaptiveRateController {

    private static final long LONG_MANUAL_PAUSE_NANOS = TimeUnit.SECONDS.toNanos(30);

    /** Tunable constants for the control law. Exposed so the simulation matrix can optimise them. */
    public record Tuning(
        double initialRate,        // starting refill rate (req/s) before anything is known
        double minRate,            // never pace slower than this (req/s)
        double maxRate,            // never pace faster than this (req/s) -- caps an unlimited host
        double bucketSeconds,      // burst capacity = rate * bucketSeconds (tokens), floored at 1
        double slowStartGrowth,    // geometric growth per window while hunting the ceiling
        double mdFactor,           // multiplicative decrease applied to rate on a throttle
        double approachFraction,   // fraction of the (ceiling - rate) gap closed per window from below
        double probeFraction,      // base upward creep (fraction of ceiling) per window at/above ceiling
        double probeAccelSeconds,  // clean-time constant over which the upward probe step accelerates
        double maxStepFraction,    // hard cap on any single additive step as a fraction of the ceiling
        double minStep,            // smallest additive step (req/s)
        long increaseIntervalMs,   // minimum spacing between additive/geometric increases
        long mdCooldownMs          // minimum spacing between multiplicative decreases (loss events)
    ) {
        public static Tuning defaults() {
            // Constants below were selected by the AdaptiveRateControllerTest tuning sweep:
            // ~94% weighted utilisation of the true ceiling at <2% steady-state throttle across
            // sliding-window, token-bucket and fixed-window server models.
            return new Tuning(
                5.0,     // initialRate
                0.5,     // minRate
                400.0,   // maxRate
                0.4,     // bucketSeconds
                1.6,     // slowStartGrowth
                0.85,    // mdFactor
                0.30,    // approachFraction
                0.02,    // probeFraction
                8.0,     // probeAccelSeconds
                0.12,    // maxStepFraction
                0.5,     // minStep
                500,     // increaseIntervalMs
                750      // mdCooldownMs
            );
        }
    }

    public enum Phase { SLOW_START, STEADY }

    /** A throttle only lowers the ceiling if the current rate is at least this fraction of it. */
    private static final double CEILING_HIT_FRACTION = 0.8;
    /** Gentle rate trim applied to a sporadic sub-ceiling throttle (does not move the ceiling). */
    private static final double GENTLE_TRIM_FACTOR = 0.9;

    private final Tuning tuning;
    private final Set<Integer> throttleStatusCodes;
    private final LongSupplier nanoTime;
    private final LongSupplier currentTimeMillis;
    private final String label;
    private final Consumer<String> logger;

    private double rate;
    private double tokens;
    private long lastRefillNanos;
    private long lastIncreaseNanos;
    private long lastDecreaseNanos;
    private long pausedUntilNanos;
    private double ceilingEstimate;   // 0 until first throttle observed
    private Phase phase = Phase.SLOW_START;
    private boolean sawSuccessThisWindow;

    /** Generation bumped on every rate transition; stale-response filter across threads. */
    private long generation;
    private boolean manuallyPaused;
    private long manualPauseStartedNanos;

    public AdaptiveRateController(Set<Integer> throttleStatusCodes, String label,
                                  Consumer<String> logger) {
        this(Tuning.defaults(), throttleStatusCodes, System::nanoTime, System::currentTimeMillis,
            label, logger);
    }

    public AdaptiveRateController(Tuning tuning, Set<Integer> throttleStatusCodes,
                                  LongSupplier nanoTime, LongSupplier currentTimeMillis,
                                  String label, Consumer<String> logger) {
        this.tuning = tuning;
        this.throttleStatusCodes = throttleStatusCodes == null ? Set.of() : Set.copyOf(throttleStatusCodes);
        this.nanoTime = nanoTime;
        this.currentTimeMillis = currentTimeMillis;
        this.label = label == null ? "" : label;
        this.logger = logger;
        this.rate = clampRate(tuning.initialRate());
        this.tokens = capacity();
        long now = nanoTime.getAsLong();
        this.lastRefillNanos = now;
        this.lastIncreaseNanos = now;
        this.lastDecreaseNanos = now - TimeUnit.MILLISECONDS.toNanos(tuning.mdCooldownMs());
    }

    /**
     * The outcome of a non-blocking admission attempt: either a slot was granted (a token was
     * consumed and {@code generation} is valid) or the caller must wait {@code waitNanos} before a
     * slot will be free.
     */
    public record Reservation(boolean granted, long waitNanos, long generation) {}

    /**
     * Non-blocking admission. If a token is available it is consumed and a granted reservation is
     * returned; otherwise the reservation reports how long to wait. This is the primitive that both
     * the blocking {@link #acquire()} and the deterministic simulation harness are built on, so they
     * exercise identical state.
     */
    public synchronized Reservation tryAcquire() {
        long now = nanoTime.getAsLong();

        if (manuallyPaused) {
            return new Reservation(false, TimeUnit.SECONDS.toNanos(1), generation);
        }
        if (pausedUntilNanos > now) {
            return new Reservation(false, pausedUntilNanos - now, generation);
        }

        refill(now);
        if (tokens >= 1.0) {
            tokens -= 1.0;
            return new Reservation(true, 0, generation);
        }

        double needed = 1.0 - tokens;
        long waitNanos = Math.max(1, (long) (needed / Math.max(tuning.minRate(), rate) * 1_000_000_000L));
        return new Reservation(false, waitNanos, generation);
    }

    /**
     * Blocks until a request slot is available under the current pace.
     *
     * @return the current {@code generation} (&ge; 0) to be passed back to
     *         {@link #report(int, String, long)}, or {@code -1} if the calling thread was interrupted.
     */
    public synchronized long acquire() {
        while (!Thread.currentThread().isInterrupted()) {
            Reservation reservation = tryAcquire();
            if (reservation.granted()) {
                return reservation.generation();
            }
            if (!timedWait(reservation.waitNanos())) {
                return -1;
            }
        }
        return -1;
    }

    /** Freezes pacing immediately and discards all accumulated burst credit. */
    public synchronized void manualPause() {
        if (manuallyPaused) return;
        manuallyPaused = true;
        manualPauseStartedNanos = nanoTime.getAsLong();
        tokens = 0;
        lastRefillNanos = manualPauseStartedNanos;
        notifyAll();
    }

    /**
     * Resumes with one token. Long pauses cold-start the learned rate so Resume cannot release a
     * stale high-rate burst that immediately recreates a WAF/CDN throttle wall.
     *
     * @return true when the controller was cold-started.
     */
    public synchronized boolean manualResume() {
        if (!manuallyPaused) return false;
        long now = nanoTime.getAsLong();
        long pausedFor = Math.max(0L, now - manualPauseStartedNanos);
        boolean coldStart = pausedFor >= LONG_MANUAL_PAUSE_NANOS;
        manuallyPaused = false;
        manualPauseStartedNanos = 0;
        tokens = Math.min(1.0, capacity());
        lastRefillNanos = now;
        lastIncreaseNanos = now;
        if (coldStart) {
            rate = clampRate(tuning.initialRate());
            ceilingEstimate = 0;
            phase = Phase.SLOW_START;
            sawSuccessThisWindow = false;
            lastDecreaseNanos = now - TimeUnit.MILLISECONDS.toNanos(tuning.mdCooldownMs());
            generation++;
        }
        notifyAll();
        return coldStart;
    }

    /**
     * Feeds a response back into the control law.
     *
     * @param statusCode     HTTP status of the response (any non-throttle code counts as a landed
     *                       request, including 401/403/404 which are valid fuzzing outcomes).
     * @param retryAfter     value of the {@code Retry-After} header, or {@code null}.
     * @param generationSeen the value returned by the matching {@link #acquire()} call; a response
     *                       from a superseded generation is ignored.
     */
    public synchronized void report(int statusCode, String retryAfter, long generationSeen) {
        if (generationSeen != generation) {
            return; // stale: issued before the last rate transition (every valid caller passes a
                    // generation from tryAcquire/acquire, so a mismatch is always a superseded report)
        }

        boolean throttled = throttleStatusCodes.contains(statusCode)
            || (retryAfter != null && !retryAfter.isBlank());

        if (throttled) {
            applyThrottle(retryAfter);
        } else {
            applySuccess();
        }
    }

    private void applyThrottle(String retryAfter) {
        long now = nanoTime.getAsLong();
        long retryAfterMs = parseRetryAfterMs(retryAfter, currentTimeMillis.getAsLong());
        if (retryAfterMs > 0) {
            pausedUntilNanos = Math.max(pausedUntilNanos, now + TimeUnit.MILLISECONDS.toNanos(retryAfterMs));
        }

        // Collapse a burst of near-simultaneous throttles into one loss event.
        if (now - lastDecreaseNanos < TimeUnit.MILLISECONDS.toNanos(tuning.mdCooldownMs())) {
            generation++; // still invalidate in-flight so their successes don't re-inflate
            notifyAll();
            return;
        }

        double previous = rate;
        // Only treat this as a rate-ceiling hit (and lower the ceiling) when we were actually pushing
        // near the discovered ceiling. A throttle that arrives while cruising well below the ceiling is
        // noise -- typically a WAF anti-scanning response that fires on the request *pattern*, not the
        // rate -- so backing the rate down further would not help and would only collapse throughput.
        // Trim gently there and keep the ceiling where it is.
        boolean ceilingHit = ceilingEstimate <= 0 || rate >= ceilingEstimate * CEILING_HIT_FRACTION;
        if (ceilingHit) {
            ceilingEstimate = rate;
            rate = clampRate(rate * tuning.mdFactor());
        } else {
            rate = clampRate(rate * GENTLE_TRIM_FACTOR);
        }
        phase = Phase.STEADY;
        tokens = Math.min(tokens, capacity()); // empty any burst credit so we don't immediately re-send
        if (tokens > 1.0) {
            tokens = 1.0;
        }
        lastDecreaseNanos = now;
        lastIncreaseNanos = now; // hold the new rate briefly before probing up again
        sawSuccessThisWindow = false;
        generation++;
        log(String.format("throttle: rate %.1f -> %.1f req/s (ceiling ~%.1f)%s",
            previous, rate, ceilingEstimate, retryAfterMs > 0 ? String.format(", pausing %dms", retryAfterMs) : ""));
        notifyAll();
    }

    private void applySuccess() {
        sawSuccessThisWindow = true;
        long now = nanoTime.getAsLong();
        if (now - lastIncreaseNanos < TimeUnit.MILLISECONDS.toNanos(tuning.increaseIntervalMs())) {
            return; // only adjust once per window
        }
        lastIncreaseNanos = now;

        double previous = rate;
        if (phase == Phase.SLOW_START) {
            rate = clampRate(rate * tuning.slowStartGrowth());
        } else {
            rate = clampRate(rate + additiveStep(now));
        }
        if (rate != previous) {
            generation++;
            notifyAll();
        }
    }

    private double additiveStep(long now) {
        double gap = ceilingEstimate - rate;
        double step;
        if (gap > 0) {
            // Approaching from below: close a fraction of the gap, decelerating near the ceiling.
            step = gap * tuning.approachFraction();
        } else {
            // At or above the last known ceiling: probe upward, accelerating the longer it has been
            // since the last throttle so headroom (or a raised server limit) is reclaimed quickly
            // while the step stays gentle right after a loss.
            double cleanSeconds = Math.max(0, (now - lastDecreaseNanos) / 1_000_000_000.0);
            double accel = 1.0 + cleanSeconds / tuning.probeAccelSeconds();
            step = Math.max(1.0, ceilingEstimate) * tuning.probeFraction() * accel;
        }
        // Cap any single step so an accelerated probe cannot overshoot a hard limit and trigger a
        // throttle storm.
        double maxStep = Math.max(tuning.minStep(), ceilingEstimate * tuning.maxStepFraction());
        return Math.max(tuning.minStep(), Math.min(maxStep, step));
    }

    private void refill(long now) {
        double elapsedSeconds = (now - lastRefillNanos) / 1_000_000_000.0;
        if (elapsedSeconds > 0) {
            tokens = Math.min(capacity(), tokens + elapsedSeconds * rate);
            lastRefillNanos = now;
        }
    }

    private double capacity() {
        return Math.max(1.0, rate * tuning.bucketSeconds());
    }

    private double clampRate(double candidate) {
        return Math.max(tuning.minRate(), Math.min(tuning.maxRate(), candidate));
    }

    private boolean timedWait(long waitNanos) {
        try {
            TimeUnit.NANOSECONDS.timedWait(this, Math.max(1, waitNanos));
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    public static long parseRetryAfterMs(String value, long nowEpochMs) {
        if (value == null || value.isBlank()) {
            return 0;
        }
        try {
            return TimeUnit.SECONDS.toMillis(Math.max(0, Long.parseLong(value.trim())));
        } catch (NumberFormatException ignored) {
            try {
                return Math.max(0, ZonedDateTime.parse(value.trim(), DateTimeFormatter.RFC_1123_DATE_TIME)
                    .toInstant().toEpochMilli() - nowEpochMs);
            } catch (Exception invalidDate) {
                return 0;
            }
        }
    }

    private void log(String message) {
        if (logger != null) {
            logger.accept(label.isBlank() ? message : "[" + label + "] " + message);
        }
    }

    // Accessors for status/telemetry and tests.

    public synchronized double currentRatePerSecond() {
        return rate;
    }

    public synchronized double ceilingEstimatePerSecond() {
        return ceilingEstimate;
    }

    public synchronized Phase phase() {
        return phase;
    }

    public synchronized long generation() {
        return generation;
    }

    public synchronized boolean isPaused() {
        return pausedUntilNanos > nanoTime.getAsLong();
    }

    public String label() {
        return label;
    }
}
