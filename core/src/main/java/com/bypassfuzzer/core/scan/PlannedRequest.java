package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.HttpRequestData;

public record PlannedRequest(String family, String payload, String encoding, HttpRequestData request,
                             boolean baseline, ProbeIntent intent, String sourcePointer,
                             String targetIdentifier) {
    public PlannedRequest(String family, String payload, String encoding, HttpRequestData request,
                          boolean baseline) {
        this(family, payload, encoding, request, baseline, ProbeIntent.STANDARD, "", "");
    }

    public PlannedRequest {
        family = family == null ? "" : family;
        payload = payload == null ? "" : payload;
        encoding = encoding == null ? "" : encoding;
        if (request == null) throw new IllegalArgumentException("Planned request is required");
        intent = intent == null ? ProbeIntent.STANDARD : intent;
        sourcePointer = sourcePointer == null ? "" : sourcePointer;
        targetIdentifier = targetIdentifier == null ? "" : targetIdentifier;
    }

    public static PlannedRequest baseline(HttpRequestData request, String label) {
        return new PlannedRequest("Control", label, "", request, true);
    }
}
