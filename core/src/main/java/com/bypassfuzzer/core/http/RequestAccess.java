package com.bypassfuzzer.core.http;

import java.nio.charset.StandardCharsets;
import java.util.List;

/** Message boundary used by the shared header policy; no transport-specific algorithms. */
public interface RequestAccess<R> {
    List<HttpHeader> headers(R request);
    R removeHeader(R request, String name);
    R addHeader(R request, String name, String value);
    String method(R request);
    String url(R request);
    String body(R request);

    RequestAccess<HttpRequestData> CORE = new RequestAccess<>() {
        public List<HttpHeader> headers(HttpRequestData r) { return r.headers(); }
        public HttpRequestData removeHeader(HttpRequestData r, String n) { return r.removeHeader(n); }
        public HttpRequestData addHeader(HttpRequestData r, String n, String v) { return r.addHeader(n, v); }
        public String method(HttpRequestData r) { return r.method(); }
        public String url(HttpRequestData r) { return r.origin() + r.rawTarget(); }
        public String body(HttpRequestData r) { return new String(r.body(), StandardCharsets.UTF_8); }
    };
}
