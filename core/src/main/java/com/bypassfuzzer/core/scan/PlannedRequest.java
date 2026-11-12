package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.HttpRequestData;

public record PlannedRequest(String family, String payload, String encoding, HttpRequestData request,
                             boolean baseline, ProbeIntent intent, String sourcePointer,
                             String targetIdentifier, String playbookId, ControlRole controlRole) {
    public PlannedRequest(String family, String payload, String encoding, HttpRequestData request,
                          boolean baseline, ProbeIntent intent, String sourcePointer, String targetIdentifier) {
        this(family, payload, encoding, request, baseline, intent, sourcePointer, targetIdentifier, "",
            baseline ? ("idor.baseline.target".equals(payload) ? ControlRole.TARGET : "idor.baseline.control".equals(payload) ? ControlRole.AUTHORIZED : ControlRole.ORIGINAL) : ControlRole.NONE);
    }
    public PlannedRequest(String family, String payload, String encoding, HttpRequestData request,
                          boolean baseline) {
        this(family, payload, encoding, request, baseline, ProbeIntent.STANDARD, "", "");
    }

    public PlannedRequest {
        playbookId = playbookId == null ? "" : playbookId;
        controlRole = controlRole == null ? ControlRole.NONE : controlRole;
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

    public PlannedRequest withPlaybook(String id) { return new PlannedRequest(family, payload, encoding, request, baseline, intent, sourcePointer, targetIdentifier, id, controlRole); }

    public PlannedRequest withRequest(HttpRequestData value) {
        return new PlannedRequest(family, payload, encoding, value, baseline, intent, sourcePointer, targetIdentifier, playbookId, controlRole);
    }
}
