package com.bypassfuzzer.core.http;

import java.nio.charset.StandardCharsets;
import java.util.List;

/** Message boundary used by the shared header policy; no transport-specific algorithms. */
public interface RequestAccess<R> {
    /** Whether the wire format admits headers (HTTP/0.9 does not). */
    boolean supportsHeaders(R request);
    List<HttpHeader> headers(R request);
    R removeHeader(R request, String name);
    R addHeader(R request, String name, String value);
    String method(R request);
    String url(R request);
    String body(R request);
    default R withProtocol(R request, HttpProtocol protocol) { return request; }
    default R withPath(R request, String target) { throw new UnsupportedOperationException("Path mutation unavailable"); }

    RequestAccess<HttpRequestData> CORE = new RequestAccess<>() {
        public boolean supportsHeaders(HttpRequestData r) { return r.protocol() != HttpProtocol.HTTP_0_9; }
        public List<HttpHeader> headers(HttpRequestData r) { return r.headers(); }
        public HttpRequestData removeHeader(HttpRequestData r, String n) { return r.removeHeader(n); }
        public HttpRequestData addHeader(HttpRequestData r, String n, String v) { return r.addHeader(n, v); }
        public HttpRequestData withProtocol(HttpRequestData r, HttpProtocol p) { return r.withProtocol(p); }
        public HttpRequestData withPath(HttpRequestData r, String target) { return r.withRawTarget(target); }
        public String method(HttpRequestData r) { return r.method(); }
        public String url(HttpRequestData r) { return r.origin() + r.rawTarget(); }
        public String body(HttpRequestData r) { return new String(r.body(), StandardCharsets.UTF_8); }
    };
}
