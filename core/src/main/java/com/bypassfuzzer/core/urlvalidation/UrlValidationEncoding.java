package com.bypassfuzzer.core.urlvalidation;

public enum UrlValidationEncoding {
    RAW("Raw"),
    INTRUDERS("Intruder's"),
    EVERYTHING("Everything"),
    SPECIAL_CHARS("Special chars"),
    UNICODE_ESCAPE("Unicode escape");

    private final String label;

    UrlValidationEncoding(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

    @Override
    public String toString() {
        return label;
    }
}
