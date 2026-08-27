package com.bypassfuzzer.core.input;

import java.util.Map;

public record OpenApiOperation(String method, String url, Map<String, String> headers, String body) {
    public OpenApiOperation {
        headers = headers == null ? Map.of() : Map.copyOf(headers);
        body = body == null ? "" : body;
    }
}
