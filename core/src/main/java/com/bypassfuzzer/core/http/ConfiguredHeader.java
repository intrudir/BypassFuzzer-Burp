package com.bypassfuzzer.core.http;

/** A user-supplied header that must be present on generated requests. */
public record ConfiguredHeader(String name, String value) {
}
