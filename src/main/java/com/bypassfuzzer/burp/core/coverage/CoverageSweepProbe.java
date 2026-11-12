package com.bypassfuzzer.burp.core.coverage;

import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.requests.HttpRequest;

public record CoverageSweepProbe(
    String label,
    String family,
    HttpRequest request,
    HttpMode httpMode,
    String playbookId,
    com.bypassfuzzer.core.scan.ControlRole controlRole
) {
    public CoverageSweepProbe(String label, String family, HttpRequest request, HttpMode mode) {
        this(label,family,request,mode,"",family.equals("Control") ? com.bypassfuzzer.core.scan.ControlRole.ORIGINAL : com.bypassfuzzer.core.scan.ControlRole.NONE);
    }
    public CoverageSweepProbe(String label, String family, HttpRequest request) {
        this(label, family, request, null);
    }
}
