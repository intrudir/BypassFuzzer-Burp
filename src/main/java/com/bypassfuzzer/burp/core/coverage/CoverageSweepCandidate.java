package com.bypassfuzzer.burp.core.coverage;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.ZonedDateTime;
import java.util.Set;

public record CoverageSweepCandidate(
    HttpRequest request,
    HttpResponse originalResponse,
    String dedupeKey,
    String displayUrl,
    String method,
    String host,
    String path,
    int statusCode,
    int contentLength,
    String contentType,
    ZonedDateTime time,
    String importKey,
    Set<String> unresolvedVariables
) {
    public CoverageSweepCandidate {
        importKey = importKey == null ? "" : importKey;
        unresolvedVariables = unresolvedVariables == null ? Set.of() : Set.copyOf(unresolvedVariables);
    }

    public CoverageSweepCandidate(HttpRequest request, HttpResponse originalResponse, String dedupeKey,
                                  String displayUrl, String method, String host, String path,
                                  int statusCode, int contentLength, String contentType, ZonedDateTime time) {
        this(request, originalResponse, dedupeKey, displayUrl, method, host, path, statusCode,
            contentLength, contentType, time, "", Set.of());
    }
}
