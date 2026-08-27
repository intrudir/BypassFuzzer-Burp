package com.bypassfuzzer.core.urlvalidation;

public enum UrlValidationAttackSetting {
    DOMAIN_ALLOW_LIST_BYPASS("Domain allow list bypass"),
    FAKE_RELATIVE_URLS("Fake relative URLs"),
    LOOPBACK("Loopback"),
    IPV6("IPv6"),
    CLOUD_METADATA_ENDPOINTS("Cloud metadata endpoints"),
    URL_SPLITTING_UNICODE_CHARACTERS("URL-splitting Unicode characters"),
    NORMALIZATION_ATTACK("Normalization attack");

    private final String displayName;

    UrlValidationAttackSetting(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
