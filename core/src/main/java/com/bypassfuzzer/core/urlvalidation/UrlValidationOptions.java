package com.bypassfuzzer.core.urlvalidation;

import java.util.Set;

/** CLI-safe URL validation settings. Collaborator is deliberately absent. */
public record UrlValidationOptions(String markerText, String allowedHost, String attackerHost,
                                   String attackerScheme, Set<UrlValidationContext> payloadFamilies,
                                   Set<UrlValidationAttackSetting> attackSettings,
                                   Set<UrlValidationEncoding> encodings) {
    private static final Set<UrlValidationContext> DEFAULT_FAMILIES = Set.of(
        UrlValidationContext.ABSOLUTE_URL, UrlValidationContext.HOSTNAME);
    private static final Set<UrlValidationAttackSetting> DEFAULT_SETTINGS = Set.of(
        UrlValidationAttackSetting.DOMAIN_ALLOW_LIST_BYPASS,
        UrlValidationAttackSetting.FAKE_RELATIVE_URLS,
        UrlValidationAttackSetting.LOOPBACK);

    public String normalizedAllowedHost() { return normalizeHost(allowedHost); }
    public String normalizedAttackerHost() { return normalizeHost(attackerHost); }
    public String normalizedAttackerScheme() { return attackerScheme == null || attackerScheme.isBlank()
        ? "https" : attackerScheme.trim().toLowerCase(); }
    public Set<UrlValidationContext> normalizedPayloadFamilies() { return payloadFamilies == null || payloadFamilies.isEmpty()
        ? DEFAULT_FAMILIES : Set.copyOf(payloadFamilies); }
    public Set<UrlValidationAttackSetting> normalizedAttackSettings() { return attackSettings == null || attackSettings.isEmpty()
        ? DEFAULT_SETTINGS : Set.copyOf(attackSettings); }
    public Set<UrlValidationEncoding> effectiveEncodings() { return encodings == null || encodings.isEmpty()
        ? Set.of(UrlValidationEncoding.RAW) : Set.copyOf(encodings); }
    public String normalizedMarkerText() { return markerText == null || markerText.isBlank() ? "{INJECT}" : markerText.trim(); }

    private String normalizeHost(String value) {
        if (value == null) return "";
        String normalized = value.trim().replaceFirst("^https?://", "");
        int slash = normalized.indexOf('/');
        return slash < 0 ? normalized : normalized.substring(0, slash);
    }
}
