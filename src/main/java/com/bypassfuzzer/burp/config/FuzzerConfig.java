package com.bypassfuzzer.burp.config;

import com.bypassfuzzer.burp.core.attacks.AttackType;
import com.bypassfuzzer.burp.core.throttle.ThrottleSettings;
import com.bypassfuzzer.burp.http.ConfiguredHeader;
import com.bypassfuzzer.burp.http.UserAgentMode;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Configuration class for the BypassFuzzer.
 * Holds all settings for a fuzzing session.
 */
public class FuzzerConfig {

    // Attack types
    private boolean enableHeaderAttack = true;
    private boolean enablePathAttack = true;
    private boolean enableVerbAttack = true;
    private boolean enableParamAttack = true;
    private boolean enableTrailingDotAttack = true;
    private boolean enableProtocolAttack = true;
    private boolean enableCaseAttack = true;
    private boolean enableTrailingSlashAttack = true;
    private boolean enableExtensionAttack = true;
    private boolean enableContentTypeAttack = true;
    private boolean enableEncodingAttack = true;
    private boolean enableCookieParamAttack = true; // Debug params via Cookie header
    private boolean enableFuzzExistingCookies = true; // Fuzz existing cookies in request

    // Rate limiting (adaptive; pacing is automatic per host)
    private int concurrency = 1;
    private int perHostConcurrency = 1;
    private Set<Integer> throttleStatusCodes = new java.util.HashSet<>();
    private ThrottleSettings.Posture throttlePosture = ThrottleSettings.Posture.RIDE_HARD;
    private ThrottleSettings.PauseMode throttlePauseMode = ThrottleSettings.PauseMode.OFF;
    private long throttleFixedPauseMillis = 30_000L;
    private List<ConfiguredHeader> requestHeaders = List.of();
    private UserAgentMode userAgentMode = UserAgentMode.DISABLED;
    private long userAgentRandomizationSeed;

    // OOB payload
    private String oobPayload = null;

    // Collaborator options
    private boolean enableCollaboratorPayloads = true;

    public FuzzerConfig() {
        // Default: auto-throttle on rate limit and service unavailable
        throttleStatusCodes.add(429);
        throttleStatusCodes.add(503);
    }

    // Getters and setters

    public boolean isEnableHeaderAttack() {
        return enableHeaderAttack;
    }

    public void setEnableHeaderAttack(boolean enableHeaderAttack) {
        this.enableHeaderAttack = enableHeaderAttack;
    }

    public boolean isEnablePathAttack() {
        return enablePathAttack;
    }

    public void setEnablePathAttack(boolean enablePathAttack) {
        this.enablePathAttack = enablePathAttack;
    }

    public boolean isEnableVerbAttack() {
        return enableVerbAttack;
    }

    public void setEnableVerbAttack(boolean enableVerbAttack) {
        this.enableVerbAttack = enableVerbAttack;
    }

    public boolean isEnableParamAttack() {
        return enableParamAttack;
    }

    public void setEnableParamAttack(boolean enableParamAttack) {
        this.enableParamAttack = enableParamAttack;
    }

    public boolean isEnableTrailingDotAttack() {
        return enableTrailingDotAttack;
    }

    public void setEnableTrailingDotAttack(boolean enableTrailingDotAttack) {
        this.enableTrailingDotAttack = enableTrailingDotAttack;
    }

    public boolean isEnableProtocolAttack() {
        return enableProtocolAttack;
    }

    public void setEnableProtocolAttack(boolean enableProtocolAttack) {
        this.enableProtocolAttack = enableProtocolAttack;
    }

    public boolean isEnableCaseAttack() {
        return enableCaseAttack;
    }

    public void setEnableCaseAttack(boolean enableCaseAttack) {
        this.enableCaseAttack = enableCaseAttack;
    }

    public boolean isEnableTrailingSlashAttack() {
        return enableTrailingSlashAttack;
    }

    public void setEnableTrailingSlashAttack(boolean enableTrailingSlashAttack) {
        this.enableTrailingSlashAttack = enableTrailingSlashAttack;
    }

    public boolean isEnableExtensionAttack() {
        return enableExtensionAttack;
    }

    public void setEnableExtensionAttack(boolean enableExtensionAttack) {
        this.enableExtensionAttack = enableExtensionAttack;
    }

    public boolean isEnableContentTypeAttack() {
        return enableContentTypeAttack;
    }

    public void setEnableContentTypeAttack(boolean enableContentTypeAttack) {
        this.enableContentTypeAttack = enableContentTypeAttack;
    }

    public boolean isEnableEncodingAttack() {
        return enableEncodingAttack;
    }

    public void setEnableEncodingAttack(boolean enableEncodingAttack) {
        this.enableEncodingAttack = enableEncodingAttack;
    }

    public boolean isEnableCookieParamAttack() {
        return enableCookieParamAttack;
    }

    public void setEnableCookieParamAttack(boolean enableCookieParamAttack) {
        this.enableCookieParamAttack = enableCookieParamAttack;
    }

    public boolean isEnableFuzzExistingCookies() {
        return enableFuzzExistingCookies;
    }

    public void setEnableFuzzExistingCookies(boolean enableFuzzExistingCookies) {
        this.enableFuzzExistingCookies = enableFuzzExistingCookies;
    }

    public int getConcurrency() {
        return concurrency;
    }

    public void setConcurrency(int concurrency) {
        this.concurrency = Math.max(1, concurrency);
    }

    public int getPerHostConcurrency() {
        return perHostConcurrency;
    }

    public void setPerHostConcurrency(int perHostConcurrency) {
        this.perHostConcurrency = Math.max(1, perHostConcurrency);
    }

    public Set<Integer> getThrottleStatusCodes() {
        return throttleStatusCodes;
    }

    /**
     * Adaptive throttle configuration derived from this config. Pacing is per host and automatic;
     * the concurrency value becomes the in-flight resource cap.
     */
    public ThrottleSettings throttleSettings() {
        return new ThrottleSettings(throttleStatusCodes, Math.max(50, concurrency),
            Math.max(50, perHostConcurrency), 400.0, throttlePosture, throttlePauseMode,
            throttleFixedPauseMillis);
    }

    public void setThrottleStatusCodes(Set<Integer> throttleStatusCodes) {
        this.throttleStatusCodes = throttleStatusCodes;
    }

    public ThrottleSettings.Posture getThrottlePosture() {
        return throttlePosture;
    }

    public void setThrottlePosture(ThrottleSettings.Posture throttlePosture) {
        this.throttlePosture = throttlePosture == null ? ThrottleSettings.Posture.RIDE_HARD : throttlePosture;
    }

    public ThrottleSettings.PauseMode getThrottlePauseMode() {
        return throttlePauseMode;
    }

    public void setThrottlePauseMode(ThrottleSettings.PauseMode throttlePauseMode) {
        this.throttlePauseMode = throttlePauseMode == null
            ? ThrottleSettings.PauseMode.OFF : throttlePauseMode;
    }

    public long getThrottleFixedPauseMillis() {
        return throttleFixedPauseMillis;
    }

    public void setThrottleFixedPauseMillis(long throttleFixedPauseMillis) {
        this.throttleFixedPauseMillis = Math.max(1_000L, throttleFixedPauseMillis);
    }

    public List<ConfiguredHeader> getRequestHeaders() {
        return requestHeaders;
    }

    public void setRequestHeaders(List<ConfiguredHeader> requestHeaders) {
        this.requestHeaders = requestHeaders == null ? List.of() : List.copyOf(requestHeaders);
    }

    public UserAgentMode getUserAgentMode() {
        return userAgentMode;
    }

    public void setUserAgentMode(UserAgentMode userAgentMode) {
        this.userAgentMode = userAgentMode == null ? UserAgentMode.DISABLED : userAgentMode;
        if (this.userAgentMode == UserAgentMode.DISABLED) userAgentRandomizationSeed = 0L;
    }

    public long getUserAgentRandomizationSeed() {
        return userAgentRandomizationSeed;
    }

    public void setUserAgentRandomizationSeed(long userAgentRandomizationSeed) {
        this.userAgentRandomizationSeed = userAgentMode == UserAgentMode.DISABLED
            ? 0L : userAgentRandomizationSeed;
    }

    public String getOobPayload() {
        return oobPayload;
    }

    public void setOobPayload(String oobPayload) {
        this.oobPayload = oobPayload;
    }

    public boolean isEnableCollaboratorPayloads() {
        return enableCollaboratorPayloads;
    }

    public void setEnableCollaboratorPayloads(boolean enableCollaboratorPayloads) {
        this.enableCollaboratorPayloads = enableCollaboratorPayloads;
    }

    /**
     * Get list of enabled attack types as lowercase strings.
     */
    public Set<AttackType> getEnabledAttackTypes() {
        Set<AttackType> types = EnumSet.noneOf(AttackType.class);
        if (enableHeaderAttack) types.add(AttackType.HEADER);
        if (enablePathAttack) types.add(AttackType.PATH);
        if (enableVerbAttack) types.add(AttackType.VERB);
        if (enableParamAttack) types.add(AttackType.PARAM);
        if (enableTrailingDotAttack) types.add(AttackType.TRAILING_DOT);
        if (enableProtocolAttack) types.add(AttackType.PROTOCOL);
        if (enableCaseAttack) types.add(AttackType.CASE);
        if (enableTrailingSlashAttack) types.add(AttackType.TRAILING_SLASH);
        if (enableExtensionAttack) types.add(AttackType.EXTENSION);
        if (enableContentTypeAttack) types.add(AttackType.CONTENT_TYPE);
        if (enableEncodingAttack) types.add(AttackType.ENCODING);
        if (enableCookieParamAttack) types.add(AttackType.COOKIE);
        return types;
    }

    /**
     * Legacy helper retained while UI code still formats attack identifiers for display/logging.
     */
    public List<String> getAttackTypes() {
        List<String> types = new ArrayList<>();
        for (AttackType type : getEnabledAttackTypes()) {
            types.add(type.id());
        }
        return types;
    }
}
