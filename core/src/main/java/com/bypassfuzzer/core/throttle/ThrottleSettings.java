package com.bypassfuzzer.core.throttle;

import java.util.Set;

/**
 * Unified throttle configuration shared by every scan pipeline, replacing the scattered
 * requests-per-second / delay / auto-throttle / smart-throttle fields that used to live on each
 * option record.
 *
 * <p>The adaptive controller does the work of finding each host's ceiling, so the only knobs that
 * remain are the ones a user actually reasons about: which status codes signal a rate limit, how
 * many requests may be in flight (a resource cap, not a pacing control), a safety cap on the
 * per-host rate, and the overall posture.</p>
 */
public record ThrottleSettings(
    Set<Integer> throttleStatusCodes,
    int globalConcurrency,
    int perHostConcurrency,
    double maxRatePerHost,
    Posture posture,
    PauseMode pauseMode,
    long fixedPauseMillis
) {

    /** How aggressively to ride the discovered ceiling. */
    public enum Posture {
        /** Probe close to the ceiling; occasional throttles are the control signal and are re-queued. */
        RIDE_HARD,
        /** Hold a wider safety margin so throttles are rarer, at some cost to throughput. */
        CONSERVATIVE
    }

    public enum PauseMode {
        OFF,
        FIXED,
        SMART
    }

    public ThrottleSettings(Set<Integer> throttleStatusCodes, int globalConcurrency,
                            int perHostConcurrency, double maxRatePerHost, Posture posture) {
        this(throttleStatusCodes, globalConcurrency, perHostConcurrency, maxRatePerHost, posture,
            PauseMode.OFF, 30_000L);
    }

    public ThrottleSettings {
        throttleStatusCodes = throttleStatusCodes == null || throttleStatusCodes.isEmpty()
            ? Set.of(429, 503) : Set.copyOf(throttleStatusCodes);
        globalConcurrency = Math.max(1, globalConcurrency);
        perHostConcurrency = Math.max(1, perHostConcurrency);
        maxRatePerHost = maxRatePerHost <= 0 ? 400.0 : maxRatePerHost;
        posture = posture == null ? Posture.RIDE_HARD : posture;
        pauseMode = pauseMode == null ? PauseMode.OFF : pauseMode;
        fixedPauseMillis = Math.max(1_000L, fixedPauseMillis);
    }

    public static ThrottleSettings defaults() {
        return new ThrottleSettings(Set.of(429, 503), 200, 50, 400.0, Posture.RIDE_HARD,
            PauseMode.OFF, 30_000L);
    }

    /** The control-law tuning implied by this posture and per-host rate cap. */
    public AdaptiveRateController.Tuning tuning() {
        AdaptiveRateController.Tuning base = AdaptiveRateController.Tuning.defaults();
        AdaptiveRateController.Tuning capped = new AdaptiveRateController.Tuning(
            base.initialRate(), base.minRate(), maxRatePerHost, base.bucketSeconds(),
            base.slowStartGrowth(), base.mdFactor(), base.approachFraction(), base.probeFraction(),
            base.probeAccelSeconds(), base.maxStepFraction(), base.minStep(),
            base.increaseIntervalMs(), base.mdCooldownMs());
        if (posture == Posture.CONSERVATIVE) {
            // Wider margin: back off harder and probe upward more gently so the sawtooth stays
            // further below the true ceiling.
            return new AdaptiveRateController.Tuning(
                capped.initialRate(), capped.minRate(), capped.maxRate(), capped.bucketSeconds(),
                capped.slowStartGrowth(), 0.70, capped.approachFraction(), 0.01,
                capped.probeAccelSeconds() * 2, 0.06, capped.minStep(),
                Math.max(capped.increaseIntervalMs(), 750), capped.mdCooldownMs());
        }
        return capped;
    }
}
