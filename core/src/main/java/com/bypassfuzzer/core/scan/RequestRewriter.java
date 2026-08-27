package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.HttpHeader;
import com.bypassfuzzer.core.http.HttpRequestData;

import java.nio.charset.StandardCharsets;

final class RequestRewriter {
    private RequestRewriter() {}

    static int count(HttpRequestData request, String value) {
        if (value == null || value.isEmpty()) return 0;
        int total = occurrences(request.rawTarget(), value);
        for (HttpHeader header : request.headers()) total += occurrences(header.name(), value) + occurrences(header.value(), value);
        total += occurrences(new String(request.body(), StandardCharsets.UTF_8), value);
        return total;
    }

    static HttpRequestData replace(HttpRequestData request, String source, String replacement) {
        HttpRequestData result = new HttpRequestData(request.origin(), request.method().replace(source, replacement),
            request.rawTarget().replace(source, replacement), request.protocol(),
            request.headers().stream().map(header -> new HttpHeader(header.name().replace(source, replacement),
                header.value().replace(source, replacement))).toList(),
            new String(request.body(), StandardCharsets.UTF_8).replace(source, replacement).getBytes(StandardCharsets.UTF_8));
        return result;
    }

    private static int occurrences(String text, String value) {
        int count = 0;
        for (int index = 0; (index = text.indexOf(value, index)) >= 0; index += value.length()) count++;
        return count;
    }
}
