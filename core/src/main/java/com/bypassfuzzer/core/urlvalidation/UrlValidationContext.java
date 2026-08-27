package com.bypassfuzzer.core.urlvalidation;

public enum UrlValidationContext {
    ABSOLUTE_URL("Absolute URL"),
    HOSTNAME("Host header"),
    CORS_ORIGIN("CORS");

    private final String displayName;

    UrlValidationContext(String displayName) {
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
