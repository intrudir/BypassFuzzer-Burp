package com.bypassfuzzer.core.urlvalidation;

public record UrlValidationPayload(UrlValidationContext family, String category, UrlValidationEncoding encoding, String value) {

    public String describe(String sinkName) {
        return sinkName + " [" + family.name() + "][" + category + "][" + encoding.label() + "]: " + value;
    }
}
