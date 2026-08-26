package com.bypassfuzzer.burp.core.idor;

import com.bypassfuzzer.burp.core.throttle.ThrottleSettings;
import com.bypassfuzzer.burp.http.ConfiguredHeader;
import com.bypassfuzzer.burp.http.UserAgentMode;

import java.util.List;
import java.util.Set;

/**
 * Execution options for a single IDOR/BOLA run.
 */
public record IdorRunOptions(
    Set<Integer> throttleStatusCodes,
    int concurrency,
    int perHostConcurrency,
    ThrottleSettings.Posture posture,
    ThrottleSettings.PauseMode pauseMode,
    long fixedPauseMillis,
    List<ConfiguredHeader> requestHeaders,
    UserAgentMode userAgentMode,
    long userAgentRandomizationSeed
) {
    public IdorRunOptions {
        concurrency = Math.max(1, concurrency);
        perHostConcurrency = Math.max(1, perHostConcurrency);
        posture = posture == null ? ThrottleSettings.Posture.RIDE_HARD : posture;
        pauseMode = pauseMode == null ? ThrottleSettings.PauseMode.OFF : pauseMode;
        fixedPauseMillis = Math.max(1_000L, fixedPauseMillis);
        requestHeaders = requestHeaders == null ? List.of() : List.copyOf(requestHeaders);
        userAgentMode = userAgentMode == null ? UserAgentMode.DISABLED : userAgentMode;
        userAgentRandomizationSeed = userAgentMode == UserAgentMode.DISABLED
            ? 0L : userAgentRandomizationSeed;
    }

    public IdorRunOptions(Set<Integer> throttleStatusCodes) {
        this(throttleStatusCodes, 1, 1, ThrottleSettings.Posture.RIDE_HARD,
            ThrottleSettings.PauseMode.OFF, 30_000L, List.of(), UserAgentMode.DISABLED, 0L);
    }

    public IdorRunOptions(Set<Integer> throttleStatusCodes, List<ConfiguredHeader> requestHeaders) {
        this(throttleStatusCodes, 1, 1, ThrottleSettings.Posture.RIDE_HARD,
            ThrottleSettings.PauseMode.OFF, 30_000L, requestHeaders, UserAgentMode.DISABLED, 0L);
    }

    public IdorRunOptions(Set<Integer> throttleStatusCodes, ThrottleSettings.Posture posture,
                          List<ConfiguredHeader> requestHeaders) {
        this(throttleStatusCodes, 1, 1, posture, ThrottleSettings.PauseMode.OFF, 30_000L,
            requestHeaders, UserAgentMode.DISABLED, 0L);
    }

    /** Alias for {@link #posture()} used by the shared throttle-settings defaults. */
    public ThrottleSettings.Posture throttlePosture() {
        return posture;
    }

    /** Adaptive per-host throttle configuration shared with the other attack modes. */
    public ThrottleSettings throttleSettings() {
        return new ThrottleSettings(throttleStatusCodes, Math.max(50, concurrency),
            Math.max(50, perHostConcurrency), 400.0, posture, pauseMode, fixedPauseMillis);
    }
}
