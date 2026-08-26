package com.bypassfuzzer.burp.session;

import com.bypassfuzzer.burp.config.FuzzerConfig;
import com.bypassfuzzer.burp.core.attacks.AttackType;
import com.bypassfuzzer.burp.core.throttle.ThrottleSettings;
import com.bypassfuzzer.burp.http.ConfiguredHeader;
import com.bypassfuzzer.burp.http.UserAgentMode;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

public record SessionRunOptions(
    boolean headerAttack,
    boolean pathAttack,
    boolean verbAttack,
    boolean paramAttack,
    boolean trailingDotAttack,
    boolean trailingSlashAttack,
    boolean extensionAttack,
    boolean contentTypeAttack,
    boolean encodingAttack,
    boolean protocolAttack,
    boolean caseAttack,
    boolean collaboratorPayloads,
    boolean cookieParamAttack,
    boolean fuzzExistingCookies,
    int concurrency,
    int perHostConcurrency,
    Set<Integer> throttleStatusCodes,
    ThrottleSettings.Posture posture,
    ThrottleSettings.PauseMode pauseMode,
    long fixedPauseMillis,
    List<ConfiguredHeader> requestHeaders,
    UserAgentMode userAgentMode,
    long userAgentRandomizationSeed
) {

    public SessionRunOptions {
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

    public SessionRunOptions(boolean headerAttack, boolean pathAttack, boolean verbAttack,
                             boolean paramAttack, boolean trailingDotAttack, boolean trailingSlashAttack,
                             boolean extensionAttack, boolean contentTypeAttack, boolean encodingAttack,
                             boolean protocolAttack, boolean caseAttack, boolean collaboratorPayloads,
                             boolean cookieParamAttack, boolean fuzzExistingCookies, int concurrency,
                             Set<Integer> throttleStatusCodes, ThrottleSettings.Posture posture,
                             List<ConfiguredHeader> requestHeaders) {
        this(headerAttack, pathAttack, verbAttack, paramAttack, trailingDotAttack, trailingSlashAttack,
            extensionAttack, contentTypeAttack, encodingAttack, protocolAttack, caseAttack,
            collaboratorPayloads, cookieParamAttack, fuzzExistingCookies, concurrency, 1,
            throttleStatusCodes, posture, ThrottleSettings.PauseMode.OFF, 30_000L, requestHeaders,
            UserAgentMode.DISABLED, 0L);
    }

    /** Convenience: default posture, without an explicit request-header list. */
    public SessionRunOptions(boolean headerAttack, boolean pathAttack, boolean verbAttack,
                             boolean paramAttack, boolean trailingDotAttack, boolean trailingSlashAttack,
                             boolean extensionAttack, boolean contentTypeAttack, boolean encodingAttack,
                             boolean protocolAttack, boolean caseAttack, boolean collaboratorPayloads,
                             boolean cookieParamAttack, boolean fuzzExistingCookies, int concurrency,
                             Set<Integer> throttleStatusCodes) {
        this(headerAttack, pathAttack, verbAttack, paramAttack, trailingDotAttack, trailingSlashAttack,
            extensionAttack, contentTypeAttack, encodingAttack, protocolAttack, caseAttack,
            collaboratorPayloads, cookieParamAttack, fuzzExistingCookies, concurrency,
            1, throttleStatusCodes, ThrottleSettings.Posture.RIDE_HARD,
            ThrottleSettings.PauseMode.OFF, 30_000L, List.of(), UserAgentMode.DISABLED, 0L);
    }

    public Set<AttackType> enabledAttackTypes() {
        Set<AttackType> types = EnumSet.noneOf(AttackType.class);
        if (headerAttack) types.add(AttackType.HEADER);
        if (pathAttack) types.add(AttackType.PATH);
        if (verbAttack) types.add(AttackType.VERB);
        if (paramAttack) types.add(AttackType.PARAM);
        if (trailingDotAttack) types.add(AttackType.TRAILING_DOT);
        if (trailingSlashAttack) types.add(AttackType.TRAILING_SLASH);
        if (extensionAttack) types.add(AttackType.EXTENSION);
        if (contentTypeAttack) types.add(AttackType.CONTENT_TYPE);
        if (encodingAttack) types.add(AttackType.ENCODING);
        if (protocolAttack) types.add(AttackType.PROTOCOL);
        if (caseAttack) types.add(AttackType.CASE);
        if (cookieParamAttack) types.add(AttackType.COOKIE);
        return types;
    }

    public boolean hasEnabledAttacks() {
        return !enabledAttackTypes().isEmpty();
    }

    public ThrottleSettings throttleSettings() {
        return new ThrottleSettings(throttleStatusCodes, Math.max(50, concurrency),
            Math.max(50, perHostConcurrency), 400.0, posture, pauseMode, fixedPauseMillis);
    }

    public SessionRunOptions withoutCollaboratorPayloads() {
        return new SessionRunOptions(
            headerAttack,
            pathAttack,
            verbAttack,
            paramAttack,
            trailingDotAttack,
            trailingSlashAttack,
            extensionAttack,
            contentTypeAttack,
            encodingAttack,
            protocolAttack,
            caseAttack,
            false,
            cookieParamAttack,
            fuzzExistingCookies,
            concurrency,
            perHostConcurrency,
            throttleStatusCodes,
            posture,
            pauseMode,
            fixedPauseMillis,
            requestHeaders,
            userAgentMode,
            userAgentRandomizationSeed
        );
    }

    public void applyTo(FuzzerConfig config) {
        config.setEnableHeaderAttack(headerAttack);
        config.setEnablePathAttack(pathAttack);
        config.setEnableVerbAttack(verbAttack);
        config.setEnableParamAttack(paramAttack);
        config.setEnableTrailingDotAttack(trailingDotAttack);
        config.setEnableTrailingSlashAttack(trailingSlashAttack);
        config.setEnableExtensionAttack(extensionAttack);
        config.setEnableContentTypeAttack(contentTypeAttack);
        config.setEnableEncodingAttack(encodingAttack);
        config.setEnableProtocolAttack(protocolAttack);
        config.setEnableCaseAttack(caseAttack);
        config.setEnableCollaboratorPayloads(collaboratorPayloads);
        config.setEnableCookieParamAttack(cookieParamAttack);
        config.setEnableFuzzExistingCookies(fuzzExistingCookies);
        config.setConcurrency(concurrency);
        config.setPerHostConcurrency(perHostConcurrency);
        config.setThrottleStatusCodes(throttleStatusCodes);
        config.setThrottlePosture(posture);
        config.setThrottlePauseMode(pauseMode);
        config.setThrottleFixedPauseMillis(fixedPauseMillis);
        config.setRequestHeaders(requestHeaders);
        config.setUserAgentMode(userAgentMode);
        config.setUserAgentRandomizationSeed(userAgentRandomizationSeed);
    }
}
