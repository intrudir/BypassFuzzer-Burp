package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.HttpProtocol;
import java.time.Duration;
import java.util.Set;

/** Transport-independent execution settings shared by every scan surface. */
public record ScanOptions(HttpProtocol protocol, Duration requestTimeout, int globalConcurrency,
                          int perHostConcurrency, Set<Integer> throttleStatusCodes, int retryAttempts,
                          boolean retryStateChanging, String posture, String pauseMode,
                          long fixedPauseMillis, boolean implicitBaseline) {
    public ScanOptions(HttpProtocol protocol, Duration requestTimeout, int globalConcurrency,
                       int perHostConcurrency, Set<Integer> throttleStatusCodes, int retryAttempts,
                       boolean retryStateChanging, String posture, String pauseMode, long fixedPauseMillis) {
        this(protocol, requestTimeout, globalConcurrency, perHostConcurrency, throttleStatusCodes,
            retryAttempts, retryStateChanging, posture, pauseMode, fixedPauseMillis, true);
    }
    public ScanOptions {
        protocol = protocol == null ? HttpProtocol.AUTO : protocol;
        requestTimeout = requestTimeout == null ? Duration.ofSeconds(15) : requestTimeout;
        globalConcurrency = Math.max(1, globalConcurrency);
        perHostConcurrency = Math.max(1, Math.min(globalConcurrency, perHostConcurrency));
        throttleStatusCodes = throttleStatusCodes == null || throttleStatusCodes.isEmpty()
            ? Set.of(429, 503) : Set.copyOf(throttleStatusCodes);
        retryAttempts = Math.max(0, retryAttempts);
        posture = posture == null ? "ride-hard" : posture;
        pauseMode = pauseMode == null ? "off" : pauseMode;
        fixedPauseMillis = Math.max(1_000L, fixedPauseMillis);
    }
}
