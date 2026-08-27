package com.bypassfuzzer.core.http;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/** Immutable wire-oriented request. Header order and duplicates are significant. */
public final class HttpRequestData {
    private final TargetOrigin origin;
    private final String method;
    private final String rawTarget;
    private final HttpProtocol protocol;
    private final List<HttpHeader> headers;
    private final byte[] body;

    public HttpRequestData(TargetOrigin origin, String method, String rawTarget, HttpProtocol protocol,
                           List<HttpHeader> headers, byte[] body) {
        if (origin == null) throw new IllegalArgumentException("Target origin is required");
        if (method == null || method.isBlank() || method.chars().anyMatch(Character::isWhitespace)) {
            throw new IllegalArgumentException("HTTP method is required and cannot contain whitespace");
        }
        if (rawTarget == null || rawTarget.isBlank() || rawTarget.indexOf('\r') >= 0 || rawTarget.indexOf('\n') >= 0) {
            throw new IllegalArgumentException("Raw request target is required");
        }
        this.origin = origin;
        this.method = method;
        this.rawTarget = rawTarget;
        this.protocol = protocol == null ? HttpProtocol.AUTO : protocol;
        this.headers = List.copyOf(headers == null ? List.of() : headers);
        this.body = body == null ? new byte[0] : body.clone();
    }

    public TargetOrigin origin() { return origin; }
    public String method() { return method; }
    public String rawTarget() { return rawTarget; }
    public HttpProtocol protocol() { return protocol; }
    public List<HttpHeader> headers() { return headers; }
    public byte[] body() { return body.clone(); }

    public String path() {
        int query = rawTarget.indexOf('?');
        return query >= 0 ? rawTarget.substring(0, query) : rawTarget;
    }

    public String query() {
        int query = rawTarget.indexOf('?');
        return query >= 0 ? rawTarget.substring(query + 1) : "";
    }

    public Optional<String> firstHeader(String name) {
        return headers.stream().filter(header -> header.name().equalsIgnoreCase(name)).map(HttpHeader::value).findFirst();
    }

    public HttpRequestData withOrigin(TargetOrigin value) {
        return new HttpRequestData(value, method, rawTarget, protocol, headers, body);
    }

    public HttpRequestData withMethod(String value) {
        return new HttpRequestData(origin, value, rawTarget, protocol, headers, body);
    }

    public HttpRequestData withRawTarget(String value) {
        return new HttpRequestData(origin, method, value, protocol, headers, body);
    }

    public HttpRequestData withProtocol(HttpProtocol value) {
        return new HttpRequestData(origin, method, rawTarget, value, headers, body);
    }

    public HttpRequestData withBody(byte[] value) {
        return new HttpRequestData(origin, method, rawTarget, protocol, headers, value);
    }

    public HttpRequestData replaceBodyText(String oldValue, String newValue) {
        String text = new String(body, StandardCharsets.UTF_8);
        return withBody(text.replace(oldValue, newValue).getBytes(StandardCharsets.UTF_8));
    }

    public HttpRequestData upsertHeader(String name, String value) {
        List<HttpHeader> updated = new ArrayList<>();
        boolean replaced = false;
        for (HttpHeader header : headers) {
            if (header.name().equalsIgnoreCase(name)) {
                if (!replaced) updated.add(new HttpHeader(name, value));
                replaced = true;
            } else {
                updated.add(header);
            }
        }
        if (!replaced) updated.add(new HttpHeader(name, value));
        return new HttpRequestData(origin, method, rawTarget, protocol, updated, body);
    }

    public HttpRequestData addHeader(String name, String value) {
        List<HttpHeader> updated = new ArrayList<>(headers);
        updated.add(new HttpHeader(name, value));
        return new HttpRequestData(origin, method, rawTarget, protocol, updated, body);
    }

    public HttpRequestData removeHeader(String name) {
        return new HttpRequestData(origin, method, rawTarget, protocol,
            headers.stream().filter(header -> !header.name().equalsIgnoreCase(name)).toList(), body);
    }

    public HttpRequestData withSyncedContentLength() {
        if (firstHeader("Transfer-Encoding").isPresent()) return removeHeader("Content-Length");
        if (body.length == 0 && firstHeader("Content-Length").isEmpty()) return this;
        return upsertHeader("Content-Length", String.valueOf(body.length));
    }

    public String toRaw() {
        String version = switch (protocol) {
            case HTTP_1_0 -> "HTTP/1.0";
            case HTTP_0_9 -> "";
            default -> "HTTP/1.1";
        };
        StringBuilder raw = new StringBuilder(method).append(' ').append(rawTarget);
        if (!version.isEmpty()) raw.append(' ').append(version);
        raw.append("\r\n");
        if (protocol != HttpProtocol.HTTP_0_9) {
            for (HttpHeader header : headers) raw.append(header.name()).append(": ").append(header.value()).append("\r\n");
            raw.append("\r\n");
        }
        byte[] prefix = raw.toString().getBytes(StandardCharsets.ISO_8859_1);
        byte[] result = Arrays.copyOf(prefix, prefix.length + body.length);
        System.arraycopy(body, 0, result, prefix.length, body.length);
        return new String(result, StandardCharsets.ISO_8859_1);
    }

    public String targetLabel() {
        return method.toUpperCase(Locale.ROOT) + " " + origin + rawTarget;
    }
}
