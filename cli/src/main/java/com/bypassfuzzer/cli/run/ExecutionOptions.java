package com.bypassfuzzer.cli.run;

import com.bypassfuzzer.core.http.HttpProtocol;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Set;

public record ExecutionOptions(Path outputDirectory, HttpProtocol protocol, Duration requestTimeout,
                               int globalConcurrency, int perHostConcurrency,
                               Set<Integer> throttleStatusCodes, boolean redact, int retryAttempts,
                               String posture, String pauseMode, long fixedPauseMillis) {
    public ExecutionOptions {
        if (outputDirectory == null) throw new IllegalArgumentException("Output directory is required");
        protocol = protocol == null ? HttpProtocol.AUTO : protocol;
        requestTimeout = requestTimeout == null ? Duration.ofSeconds(15) : requestTimeout;
        globalConcurrency = Math.max(1, globalConcurrency);
        perHostConcurrency = Math.max(1, Math.min(globalConcurrency, perHostConcurrency));
        throttleStatusCodes = throttleStatusCodes == null || throttleStatusCodes.isEmpty()
            ? Set.of(429, 503) : Set.copyOf(throttleStatusCodes);
        retryAttempts = Math.max(0, retryAttempts);
        posture = posture == null ? "ride-hard" : posture.toLowerCase();
        pauseMode = pauseMode == null ? "off" : pauseMode.toLowerCase();
        if (!(posture.equals("ride-hard") || posture.equals("conservative"))) throw new IllegalArgumentException("Posture must be ride-hard or conservative");
        if (!(pauseMode.equals("off") || pauseMode.equals("fixed") || pauseMode.equals("smart"))) throw new IllegalArgumentException("Pause mode must be off, fixed, or smart");
        fixedPauseMillis = Math.max(1_000L, fixedPauseMillis);
    }
}
