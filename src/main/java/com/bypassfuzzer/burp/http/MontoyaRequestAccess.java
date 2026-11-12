package com.bypassfuzzer.burp.http;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.core.http.HttpHeader;
import com.bypassfuzzer.core.http.RequestAccess;
import java.util.List;

/** Montoya message access only; header and User-Agent behavior lives in core. */
public final class MontoyaRequestAccess implements RequestAccess<HttpRequest> {
    public static final MontoyaRequestAccess INSTANCE = new MontoyaRequestAccess();
    public List<HttpHeader> headers(HttpRequest r) {
        return r.headers().stream().map(h -> new HttpHeader(h.name(), h.value())).toList();
    }
    public HttpRequest removeHeader(HttpRequest r, String n) { return r.withRemovedHeader(n); }
    public HttpRequest addHeader(HttpRequest r, String n, String v) { return r.withAddedHeader(n, v); }
    public HttpRequest withPath(HttpRequest r, String target) { return r.withPath(target); }
    public String method(HttpRequest r) { return r.method(); }
    public String url(HttpRequest r) { return r.url(); }
    public String body(HttpRequest r) { return r.bodyToString(); }
}
