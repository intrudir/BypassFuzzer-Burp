package com.bypassfuzzer.core.http;

import java.util.List;

public record HttpResponseData(HttpProtocol protocol, int statusCode, List<HttpHeader> headers,
                               byte[] body, long durationMillis) {
    public HttpResponseData {
        protocol = protocol == null ? HttpProtocol.HTTP_1 : protocol;
        headers = List.copyOf(headers == null ? List.of() : headers);
        body = body == null ? new byte[0] : body.clone();
        if (durationMillis < 0) durationMillis = 0;
    }

    @Override
    public byte[] body() {
        return body.clone();
    }
}
