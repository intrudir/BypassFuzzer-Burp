package com.bypassfuzzer.core.http;

public record HttpHeader(String name, String value) {
    public HttpHeader {
        if (name == null || name.isBlank() || name.indexOf('\r') >= 0 || name.indexOf('\n') >= 0
            || name.indexOf(':') >= 0) {
            throw new IllegalArgumentException("Invalid HTTP header name");
        }
        value = value == null ? "" : value;
        if (value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0) {
            throw new IllegalArgumentException("Invalid HTTP header value");
        }
    }
}
