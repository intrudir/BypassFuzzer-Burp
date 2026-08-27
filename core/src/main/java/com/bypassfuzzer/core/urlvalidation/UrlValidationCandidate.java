package com.bypassfuzzer.core.urlvalidation;

public record UrlValidationCandidate(String sinkName, String originalValue, String locationLabel) {
    public String displayName() {
        return sinkName + " (" + locationLabel + ")";
    }
}
