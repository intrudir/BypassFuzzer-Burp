package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.burp.config.FuzzerConfig;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepOptions;
import com.bypassfuzzer.burp.core.idor.IdorRunOptions;
import com.bypassfuzzer.burp.core.throttle.ThrottleSettings;

import java.util.Set;

/**
 * Default values and feature visibility for the shared throttle settings dialog. Request pacing is
 * automatic and adaptive, so only the in-flight concurrency caps, rate-limit status codes, and the
 * ride-hard vs. cautious posture remain.
 *
 * @param concurrency          initial concurrency value; -1 = don't show the field
 * @param perHostConcurrency   initial per-host concurrency; -1 = don't show the field
 * @param throttleStatusCodes  initial rate-limit status codes
 * @param posture              initial pacing posture (ride hard vs. cautious)
 * @param concurrencyLabel     label for the concurrency field ("Concurrency" vs "Global concurrency")
 */
public record ThrottleDefaults(
    int concurrency,
    int perHostConcurrency,
    Set<Integer> throttleStatusCodes,
    ThrottleSettings.Posture posture,
    String concurrencyLabel,
    boolean showGlobalPause,
    ThrottleSettings.PauseMode pauseMode,
    long fixedPauseMillis
) {

    static ThrottleDefaults forBypassFuzzer(FuzzerConfig config) {
        return new ThrottleDefaults(
            config.getConcurrency(),
            config.getPerHostConcurrency(),
            config.getThrottleStatusCodes(),
            config.getThrottlePosture(),
            "Global concurrency", true, config.getThrottlePauseMode(),
            config.getThrottleFixedPauseMillis()
        );
    }

    static ThrottleDefaults forCoverageSweep(CoverageSweepOptions defaults) {
        return new ThrottleDefaults(
            defaults.concurrency(),
            defaults.perHostConcurrency(),
            defaults.throttleStatusCodes(),
            defaults.throttlePosture(),
            "Global concurrency", true, defaults.pauseMode(), defaults.fixedPauseMillis()
        );
    }

    static ThrottleDefaults forIdor(IdorRunOptions defaults) {
        return new ThrottleDefaults(
            defaults.concurrency(),
            defaults.perHostConcurrency(),
            defaults.throttleStatusCodes(),
            defaults.throttlePosture(),
            "Global concurrency", true, defaults.pauseMode(), defaults.fixedPauseMillis()
        );
    }

    static ThrottleDefaults forUrlValidation() {
        return new ThrottleDefaults(
            1,
            1,
            Set.of(429, 503),
            ThrottleSettings.Posture.RIDE_HARD,
            "Global concurrency", true, ThrottleSettings.PauseMode.OFF, 30_000L
        );
    }
}
