package com.bypassfuzzer.burp.core.urlvalidation;

import com.bypassfuzzer.burp.core.throttle.ThrottleSettings;
import com.bypassfuzzer.burp.http.ConfiguredHeader;
import com.bypassfuzzer.burp.http.UserAgentMode;

import java.util.List;
import java.util.Set;

public record UrlValidationOptions(
    String markerText,
    String allowedHost,
    String attackerHost,
    boolean collaboratorPayloads,
    String attackerScheme,
    Set<UrlValidationContext> payloadFamilies,
    Set<UrlValidationAttackSetting> attackSettings,
    Set<UrlValidationEncoding> encodings,
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

    public UrlValidationOptions {
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

    /** Adaptive per-host throttle configuration; URL validation runs its single attack serially. */
    public ThrottleSettings throttleSettings() {
        return new ThrottleSettings(throttleStatusCodes, Math.max(50, concurrency),
            Math.max(50, perHostConcurrency), 400.0, posture, pauseMode, fixedPauseMillis);
    }

    public UrlValidationOptions(String markerText, String allowedHost, String attackerHost,
                                boolean collaboratorPayloads, String attackerScheme,
                                Set<UrlValidationContext> payloadFamilies,
                                Set<UrlValidationAttackSetting> attackSettings,
                                Set<UrlValidationEncoding> encodings,
                                Set<Integer> throttleStatusCodes) {
        this(markerText, allowedHost, attackerHost, collaboratorPayloads, attackerScheme,
            payloadFamilies, attackSettings, encodings, throttleStatusCodes, 1, 1,
            ThrottleSettings.Posture.RIDE_HARD, ThrottleSettings.PauseMode.OFF, 30_000L,
            List.of(), UserAgentMode.DISABLED, 0L);
    }

    public UrlValidationOptions(String markerText, String allowedHost, String attackerHost,
                                boolean collaboratorPayloads, String attackerScheme,
                                Set<UrlValidationContext> payloadFamilies,
                                Set<UrlValidationAttackSetting> attackSettings,
                                Set<UrlValidationEncoding> encodings,
                                Set<Integer> throttleStatusCodes,
                                ThrottleSettings.Posture posture,
                                List<ConfiguredHeader> requestHeaders) {
        this(markerText, allowedHost, attackerHost, collaboratorPayloads, attackerScheme,
            payloadFamilies, attackSettings, encodings, throttleStatusCodes, 1, 1, posture,
            ThrottleSettings.PauseMode.OFF, 30_000L, requestHeaders, UserAgentMode.DISABLED, 0L);
    }


    private static final Set<UrlValidationContext> DEFAULT_PAYLOAD_FAMILIES = Set.of(
        UrlValidationContext.ABSOLUTE_URL,
        UrlValidationContext.HOSTNAME
    );
    private static final Set<UrlValidationAttackSetting> DEFAULT_ATTACK_SETTINGS = Set.of(
        UrlValidationAttackSetting.DOMAIN_ALLOW_LIST_BYPASS,
        UrlValidationAttackSetting.FAKE_RELATIVE_URLS,
        UrlValidationAttackSetting.LOOPBACK
    );

    public String normalizedAllowedHost() {
        return normalizeHost(allowedHost);
    }

    public String normalizedAttackerHost() {
        return normalizeHost(attackerHost);
    }

    public boolean useCollaboratorPayloads() {
        return collaboratorPayloads;
    }

    public String normalizedAttackerScheme() {
        if (attackerScheme == null || attackerScheme.isBlank()) {
            return "https";
        }
        return attackerScheme.trim().toLowerCase();
    }

    public Set<UrlValidationContext> normalizedPayloadFamilies() {
        return payloadFamilies == null ? DEFAULT_PAYLOAD_FAMILIES : Set.copyOf(payloadFamilies);
    }

    public Set<UrlValidationAttackSetting> normalizedAttackSettings() {
        return attackSettings == null ? DEFAULT_ATTACK_SETTINGS : Set.copyOf(attackSettings);
    }

    public Set<UrlValidationEncoding> effectiveEncodings() {
        if (encodings == null || encodings.isEmpty()) {
            return Set.of(UrlValidationEncoding.RAW);
        }
        return Set.copyOf(encodings);
    }

    public String normalizedMarkerText() {
        if (markerText == null || markerText.isBlank()) {
            return "{INJECT}";
        }
        return markerText.trim();
    }

    private String normalizeHost(String value) {
        if (value == null) {
            return "";
        }

        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            return "";
        }

        String normalized = trimmed.replaceFirst("^https?://", "");
        int slashIndex = normalized.indexOf('/');
        if (slashIndex >= 0) {
            normalized = normalized.substring(0, slashIndex);
        }
        return normalized;
    }
}
