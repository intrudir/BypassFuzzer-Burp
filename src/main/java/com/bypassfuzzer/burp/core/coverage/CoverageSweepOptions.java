package com.bypassfuzzer.burp.core.coverage;

import com.bypassfuzzer.burp.core.throttle.ThrottleSettings;
import com.bypassfuzzer.burp.http.ConfiguredHeader;
import com.bypassfuzzer.burp.http.UserAgentMode;

import java.util.List;
import java.util.Set;

public record CoverageSweepOptions(
    Set<Integer> statuses,
    boolean inScopeOnly,
    int maxCandidates,
    int maxProbesPerCandidate,
    int concurrency,
    int perHostConcurrency,
    Set<Integer> throttleStatusCodes,
    CoverageSweepMode mode,
    CoverageSweepAuthSelection authSelection,
    boolean excludeStaticAssets,
    boolean verifyUnauthenticatedAccess,
    List<Integer> hostPortProbePorts,
    List<ConfiguredHeader> requestHeaders,
    CoverageSweepPayloadSet payloadSet,
    ThrottleSettings.Posture posture,
    CoverageSweepFamilySelection familySelection,
    ThrottleSettings.PauseMode pauseMode,
    long fixedPauseMillis,
    UserAgentMode userAgentMode,
    long userAgentRandomizationSeed
) {

    public CoverageSweepOptions {
        mode = mode == null ? CoverageSweepMode.BLOCKED_RESPONSES : mode;
        authSelection = authSelection == null ? CoverageSweepAuthSelection.defaults() : authSelection;
        hostPortProbePorts = hostPortProbePorts == null ? List.of() : List.copyOf(hostPortProbePorts);
        requestHeaders = requestHeaders == null ? List.of() : List.copyOf(requestHeaders);
        payloadSet = payloadSet == null ? CoverageSweepPayloadSet.HIGH_SIGNAL : payloadSet;
        posture = posture == null ? ThrottleSettings.Posture.RIDE_HARD : posture;
        familySelection = familySelection == null ? CoverageSweepFamilySelection.defaults() : familySelection;
        pauseMode = pauseMode == null ? ThrottleSettings.PauseMode.OFF : pauseMode;
        fixedPauseMillis = Math.max(1_000L, fixedPauseMillis);
        perHostConcurrency = Math.max(1, perHostConcurrency);
        userAgentMode = userAgentMode == null ? UserAgentMode.DISABLED : userAgentMode;
        userAgentRandomizationSeed = userAgentMode == UserAgentMode.DISABLED
            ? 0L : userAgentRandomizationSeed;
    }

    /** Full constructor retained for callers that do not use User-Agent randomization. */
    public CoverageSweepOptions(Set<Integer> statuses, boolean inScopeOnly, int maxCandidates,
                                int maxProbesPerCandidate, int concurrency, int perHostConcurrency,
                                Set<Integer> throttleStatusCodes, CoverageSweepMode mode,
                                CoverageSweepAuthSelection authSelection, boolean excludeStaticAssets,
                                boolean verifyUnauthenticatedAccess, List<Integer> hostPortProbePorts,
                                List<ConfiguredHeader> requestHeaders, CoverageSweepPayloadSet payloadSet,
                                ThrottleSettings.Posture posture, CoverageSweepFamilySelection familySelection,
                                ThrottleSettings.PauseMode pauseMode, long fixedPauseMillis) {
        this(statuses, inScopeOnly, maxCandidates, maxProbesPerCandidate, concurrency,
            perHostConcurrency, throttleStatusCodes, mode, authSelection, excludeStaticAssets,
            verifyUnauthenticatedAccess, hostPortProbePorts, requestHeaders, payloadSet, posture,
            familySelection, pauseMode, fixedPauseMillis, UserAgentMode.DISABLED, 0L);
    }

    /** Backward-compatible full constructor with no global throttle pause. */
    public CoverageSweepOptions(Set<Integer> statuses, boolean inScopeOnly, int maxCandidates,
                                int maxProbesPerCandidate, int concurrency, int perHostConcurrency,
                                Set<Integer> throttleStatusCodes, CoverageSweepMode mode,
                                CoverageSweepAuthSelection authSelection, boolean excludeStaticAssets,
                                boolean verifyUnauthenticatedAccess, List<Integer> hostPortProbePorts,
                                List<ConfiguredHeader> requestHeaders, CoverageSweepPayloadSet payloadSet,
                                ThrottleSettings.Posture posture, CoverageSweepFamilySelection familySelection) {
        this(statuses, inScopeOnly, maxCandidates, maxProbesPerCandidate, concurrency,
            perHostConcurrency, throttleStatusCodes, mode, authSelection, excludeStaticAssets,
            verifyUnauthenticatedAccess, hostPortProbePorts, requestHeaders, payloadSet, posture,
            familySelection, ThrottleSettings.PauseMode.OFF, 30_000L);
    }

    /** Backward-compatible full constructor with all payload families enabled. */
    public CoverageSweepOptions(Set<Integer> statuses, boolean inScopeOnly, int maxCandidates,
                                int maxProbesPerCandidate, int concurrency, int perHostConcurrency,
                                Set<Integer> throttleStatusCodes, CoverageSweepMode mode,
                                CoverageSweepAuthSelection authSelection, boolean excludeStaticAssets,
                                boolean verifyUnauthenticatedAccess, List<Integer> hostPortProbePorts,
                                List<ConfiguredHeader> requestHeaders, CoverageSweepPayloadSet payloadSet,
                                ThrottleSettings.Posture posture) {
        this(statuses, inScopeOnly, maxCandidates, maxProbesPerCandidate, concurrency,
            perHostConcurrency, throttleStatusCodes, mode, authSelection, excludeStaticAssets,
            verifyUnauthenticatedAccess, hostPortProbePorts, requestHeaders, payloadSet, posture,
            CoverageSweepFamilySelection.defaults());
    }

    /** Alias for {@link #posture()} used by the shared throttle-settings defaults. */
    public ThrottleSettings.Posture throttlePosture() {
        return posture;
    }

    public boolean hostPortProbesEnabled() {
        return !hostPortProbePorts.isEmpty();
    }

    /** Convenience: blocked-response defaults with explicit concurrency and throttle codes. */
    public CoverageSweepOptions(Set<Integer> statuses, boolean inScopeOnly, int maxCandidates,
                                int maxProbesPerCandidate, int concurrency, int perHostConcurrency,
                                Set<Integer> throttleStatusCodes) {
        this(statuses, inScopeOnly, maxCandidates, maxProbesPerCandidate, concurrency,
            perHostConcurrency, throttleStatusCodes, CoverageSweepMode.BLOCKED_RESPONSES,
            CoverageSweepAuthSelection.defaults(), true, false, List.of(), List.of(),
            CoverageSweepPayloadSet.HIGH_SIGNAL, ThrottleSettings.Posture.RIDE_HARD);
    }

    /** Convenience: adds mode + auth selection. */
    public CoverageSweepOptions(Set<Integer> statuses, boolean inScopeOnly, int maxCandidates,
                                int maxProbesPerCandidate, int concurrency, int perHostConcurrency,
                                Set<Integer> throttleStatusCodes, CoverageSweepMode mode,
                                CoverageSweepAuthSelection authSelection) {
        this(statuses, inScopeOnly, maxCandidates, maxProbesPerCandidate, concurrency,
            perHostConcurrency, throttleStatusCodes, mode, authSelection, true, false, List.of(),
            List.of(), CoverageSweepPayloadSet.HIGH_SIGNAL, ThrottleSettings.Posture.RIDE_HARD);
    }

    /** Convenience: adds mode + auth + static-asset / unauthenticated toggles. */
    public CoverageSweepOptions(Set<Integer> statuses, boolean inScopeOnly, int maxCandidates,
                                int maxProbesPerCandidate, int concurrency, int perHostConcurrency,
                                Set<Integer> throttleStatusCodes, CoverageSweepMode mode,
                                CoverageSweepAuthSelection authSelection, boolean excludeStaticAssets,
                                boolean verifyUnauthenticatedAccess) {
        this(statuses, inScopeOnly, maxCandidates, maxProbesPerCandidate, concurrency,
            perHostConcurrency, throttleStatusCodes, mode, authSelection, excludeStaticAssets,
            verifyUnauthenticatedAccess, List.of(), List.of(), CoverageSweepPayloadSet.HIGH_SIGNAL, ThrottleSettings.Posture.RIDE_HARD);
    }

    /** Convenience: adds mode + auth + toggles + host-port probe ports. */
    public CoverageSweepOptions(Set<Integer> statuses, boolean inScopeOnly, int maxCandidates,
                                int maxProbesPerCandidate, int concurrency, int perHostConcurrency,
                                Set<Integer> throttleStatusCodes, CoverageSweepMode mode,
                                CoverageSweepAuthSelection authSelection, boolean excludeStaticAssets,
                                boolean verifyUnauthenticatedAccess, List<Integer> hostPortProbePorts) {
        this(statuses, inScopeOnly, maxCandidates, maxProbesPerCandidate, concurrency,
            perHostConcurrency, throttleStatusCodes, mode, authSelection, excludeStaticAssets,
            verifyUnauthenticatedAccess, hostPortProbePorts, List.of(),
            CoverageSweepPayloadSet.HIGH_SIGNAL, ThrottleSettings.Posture.RIDE_HARD);
    }

    /** The adaptive-throttle configuration for this run. Concurrency values are hard in-flight caps. */
    public ThrottleSettings throttleSettings() {
        return new ThrottleSettings(throttleStatusCodes, concurrency, perHostConcurrency, 400.0, posture,
            pauseMode, fixedPauseMillis);
    }

    public static CoverageSweepOptions defaults() {
        return new CoverageSweepOptions(
            Set.of(401, 403),
            true,
            100,
            350,
            1,
            1,
            Set.of(429, 503),
            CoverageSweepMode.BLOCKED_RESPONSES,
            CoverageSweepAuthSelection.defaults(),
            true,
            true,
            List.of(0),
            List.of(),
            CoverageSweepPayloadSet.HIGH_SIGNAL,
            ThrottleSettings.Posture.RIDE_HARD,
            CoverageSweepFamilySelection.defaults(),
            ThrottleSettings.PauseMode.OFF,
            30_000L,
            UserAgentMode.DISABLED,
            0L
        );
    }

    public CoverageSweepOptions withAuthenticatedTraffic(CoverageSweepAuthSelection selection) {
        return new CoverageSweepOptions(Set.of(), inScopeOnly, maxCandidates, maxProbesPerCandidate,
            concurrency, perHostConcurrency, throttleStatusCodes,
            CoverageSweepMode.AUTHENTICATED_TRAFFIC, selection, excludeStaticAssets,
            verifyUnauthenticatedAccess, hostPortProbePorts, requestHeaders, payloadSet, posture,
            familySelection, pauseMode, fixedPauseMillis, userAgentMode, userAgentRandomizationSeed);
    }

    public CoverageSweepOptions withHostPortProbePorts(List<Integer> ports) {
        return new CoverageSweepOptions(statuses, inScopeOnly, maxCandidates, maxProbesPerCandidate,
            concurrency, perHostConcurrency, throttleStatusCodes, mode, authSelection,
            excludeStaticAssets, verifyUnauthenticatedAccess, ports, requestHeaders, payloadSet, posture,
            familySelection, pauseMode, fixedPauseMillis, userAgentMode, userAgentRandomizationSeed);
    }
}
