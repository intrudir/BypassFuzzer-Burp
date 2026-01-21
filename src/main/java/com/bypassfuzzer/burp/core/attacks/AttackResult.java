package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * Represents the result of a single attack attempt.
 */
public class AttackResult {
    private final String attackType;
    private final String payload;
    private final HttpRequest request;
    private final HttpResponse response;
    private final int statusCode;
    private final int contentLength;
    private final String contentType;
    private final long timestamp;

    public AttackResult(String attackType, String payload, HttpRequest request, HttpResponse response) {
        this.attackType = attackType;
        this.payload = payload;
        this.request = request;
        this.response = response;
        this.statusCode = response != null ? response.statusCode() : 0;
        this.contentLength = response != null ? response.body().length() : 0;
        this.contentType = response != null ? extractContentType(response) : "";
        this.timestamp = System.currentTimeMillis();
    }

    private String extractContentType(HttpResponse response) {
        return response.headers().stream()
            .filter(h -> h.name().equalsIgnoreCase("Content-Type"))
            .map(h -> h.value())
            .findFirst()
            .orElse("");
    }

    public String getAttackType() {
        return attackType;
    }

    public String getPayload() {
        return payload;
    }

    public HttpRequest getRequest() {
        return request;
    }

    public HttpResponse getResponse() {
        return response;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public int getContentLength() {
        return contentLength;
    }

    public String getContentType() {
        return contentType;
    }

    public long getTimestamp() {
        return timestamp;
    }

    @Override
    public String toString() {
        return String.format("[%s] %s -> %d (%d bytes)", attackType, payload, statusCode, contentLength);
    }
}
