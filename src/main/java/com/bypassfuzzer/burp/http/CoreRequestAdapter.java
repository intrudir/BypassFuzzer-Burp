package com.bypassfuzzer.burp.http;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpHeader;
import com.bypassfuzzer.core.http.HttpProtocol;
import com.bypassfuzzer.core.http.HttpRequestData;
import com.bypassfuzzer.core.http.RawHttpRequestParser;
import com.bypassfuzzer.core.http.TargetOrigin;

/** Lossless boundary between Burp's Montoya messages and the shared core request model. */
public final class CoreRequestAdapter {
    private final RawHttpRequestParser parser = new RawHttpRequestParser();

    public HttpRequestData fromMontoya(HttpRequest request) {
        if (request == null || request.httpService() == null) {
            throw new IllegalArgumentException("A request with an HTTP service is required");
        }
        HttpService service = request.httpService();
        TargetOrigin origin = new TargetOrigin(service.secure() ? "https" : "http", service.host(), service.port());
        ByteArray bytes = request.toByteArray();
        byte[] raw = bytes == null
            ? request.toString().getBytes(java.nio.charset.StandardCharsets.ISO_8859_1)
            : bytes.getBytes();
        return parser.parse(raw, origin);
    }

    public HttpRequest toMontoya(HttpRequest original, HttpRequestData request) {
        HttpRequestData normalized = request.withSyncedContentLength();
        if (original.toByteArray() == null) {
            HttpRequest rebuilt = original.withMethod(normalized.method()).withPath(normalized.rawTarget());
            for (HttpHeader header : original.headers()) rebuilt = rebuilt.withRemovedHeader(header.name());
            for (com.bypassfuzzer.core.http.HttpHeader header : normalized.headers()) {
                rebuilt = rebuilt.withAddedHeader(header.name(), header.value());
            }
            return rebuilt.withBody(new String(normalized.body(), java.nio.charset.StandardCharsets.ISO_8859_1));
        }
        return HttpRequest.httpRequest(original.httpService(), ByteArray.byteArray(
            normalized.toRaw().getBytes(java.nio.charset.StandardCharsets.ISO_8859_1)));
    }

    public HttpMode httpMode(HttpProtocol protocol) {
        return protocol == HttpProtocol.HTTP_2 ? HttpMode.HTTP_2
            : protocol == HttpProtocol.HTTP_1 || protocol == HttpProtocol.HTTP_1_0 || protocol == HttpProtocol.HTTP_0_9
            ? HttpMode.HTTP_1 : null;
    }
}
