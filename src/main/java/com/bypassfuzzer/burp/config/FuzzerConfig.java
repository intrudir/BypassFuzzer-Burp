package com.bypassfuzzer.burp.config;

import java.util.HashSet;
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

    // Filtering options
    private boolean enableSmartFilter = true;
    private int smartFilterRepeats = 8;
    private Set<Integer> hiddenStatusCodes = new HashSet<>();
    private Set<Integer> hiddenLengths = new HashSet<>();

    // Database options
    private Set<Integer> saveStatusCodes = new HashSet<>();

    // Rate limiting
    private int requestsPerSecond = 0; // 0 = unlimited (default)
    private Set<Integer> throttleStatusCodes = new HashSet<>();
    private boolean enableAutoThrottle = true;

    // Custom payloads
    private String customHeaderPayloadPath = null;
    private String customIpPayloadPath = null;
    private String customUrlPayloadPath = null;

    // OOB payload
    private String oobPayload = null;

    // Collaborator options
    private boolean enableCollaboratorPayloads = false;

    public FuzzerConfig() {
        // Default: save 2xx and 3xx responses
        saveStatusCodes.add(200);
        saveStatusCodes.add(201);
        saveStatusCodes.add(301);
        saveStatusCodes.add(302);
        saveStatusCodes.add(307);
        saveStatusCodes.add(308);

        // Default: hide common error codes
        hiddenStatusCodes.add(401);
        hiddenStatusCodes.add(403);
        hiddenStatusCodes.add(404);

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

    public boolean isEnableSmartFilter() {
        return enableSmartFilter;
    }

    public void setEnableSmartFilter(boolean enableSmartFilter) {
        this.enableSmartFilter = enableSmartFilter;
    }

    public int getSmartFilterRepeats() {
        return smartFilterRepeats;
    }

    public void setSmartFilterRepeats(int smartFilterRepeats) {
        this.smartFilterRepeats = smartFilterRepeats;
    }

    public Set<Integer> getHiddenStatusCodes() {
        return hiddenStatusCodes;
    }

    public void setHiddenStatusCodes(Set<Integer> hiddenStatusCodes) {
        this.hiddenStatusCodes = hiddenStatusCodes;
    }

    public Set<Integer> getHiddenLengths() {
        return hiddenLengths;
    }

    public void setHiddenLengths(Set<Integer> hiddenLengths) {
        this.hiddenLengths = hiddenLengths;
    }

    public Set<Integer> getSaveStatusCodes() {
        return saveStatusCodes;
    }

    public void setSaveStatusCodes(Set<Integer> saveStatusCodes) {
        this.saveStatusCodes = saveStatusCodes;
    }

    public int getRequestsPerSecond() {
        return requestsPerSecond;
    }

    public void setRequestsPerSecond(int requestsPerSecond) {
        this.requestsPerSecond = requestsPerSecond;
    }

    public Set<Integer> getThrottleStatusCodes() {
        return throttleStatusCodes;
    }

    public void setThrottleStatusCodes(Set<Integer> throttleStatusCodes) {
        this.throttleStatusCodes = throttleStatusCodes;
    }

    public boolean isEnableAutoThrottle() {
        return enableAutoThrottle;
    }

    public void setEnableAutoThrottle(boolean enableAutoThrottle) {
        this.enableAutoThrottle = enableAutoThrottle;
    }

    public String getCustomHeaderPayloadPath() {
        return customHeaderPayloadPath;
    }

    public void setCustomHeaderPayloadPath(String customHeaderPayloadPath) {
        this.customHeaderPayloadPath = customHeaderPayloadPath;
    }

    public String getCustomIpPayloadPath() {
        return customIpPayloadPath;
    }

    public void setCustomIpPayloadPath(String customIpPayloadPath) {
        this.customIpPayloadPath = customIpPayloadPath;
    }

    public String getCustomUrlPayloadPath() {
        return customUrlPayloadPath;
    }

    public void setCustomUrlPayloadPath(String customUrlPayloadPath) {
        this.customUrlPayloadPath = customUrlPayloadPath;
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
    public java.util.List<String> getAttackTypes() {
        java.util.List<String> types = new java.util.ArrayList<>();
        if (enableHeaderAttack) types.add("header");
        if (enablePathAttack) types.add("path");
        if (enableVerbAttack) types.add("verb");
        if (enableParamAttack) types.add("param");
        if (enableTrailingDotAttack) types.add("trailingdot");
        if (enableProtocolAttack) types.add("protocol");
        if (enableCaseAttack) types.add("case");
        if (enableTrailingSlashAttack) types.add("trailingslash");
        return types;
    }
}
