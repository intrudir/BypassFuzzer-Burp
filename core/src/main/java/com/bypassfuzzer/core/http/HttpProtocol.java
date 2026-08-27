package com.bypassfuzzer.core.http;

public enum HttpProtocol {
    AUTO("auto"),
    HTTP_1("http1"),
    HTTP_1_0("http1.0"),
    HTTP_0_9("http0.9"),
    HTTP_2("http2"),
    BOTH("both");

    private final String id;

    HttpProtocol(String id) {
        this.id = id;
    }

    public String id() {
        return id;
    }

    public static HttpProtocol parse(String value) {
        for (HttpProtocol protocol : values()) {
            if (protocol.id.equalsIgnoreCase(value) || protocol.name().equalsIgnoreCase(value)) {
                return protocol;
            }
        }
        throw new IllegalArgumentException("Unknown HTTP protocol: " + value);
    }
}
