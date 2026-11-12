package com.bypassfuzzer.core.input;

import com.bypassfuzzer.core.http.*;
import com.bypassfuzzer.core.scan.PlannedRequest;
import java.net.URI;
import java.nio.charset.StandardCharsets;

public record RetryPackageEntry(String targetLabel, String payload, String payloadFamily,
    String payloadEncoding, int retryAttempt, String requestRaw, String url, String method,
    String httpMode, String payloadLabel, String playbookId, com.bypassfuzzer.core.scan.ControlRole controlRole) {
    public RetryPackageEntry(String targetLabel, String payload, String payloadFamily, String payloadEncoding, int retryAttempt,
        String requestRaw, String url, String method, String httpMode, String payloadLabel) {
        this(targetLabel,payload,payloadFamily,payloadEncoding,retryAttempt,requestRaw,url,method,httpMode,payloadLabel,"",com.bypassfuzzer.core.scan.ControlRole.NONE);
    }
    public PlannedRequest planned() {
        if (requestRaw == null || url == null) throw new IllegalArgumentException("Retry entry lacks requestRaw or url");
        URI uri = URI.create(url);
        TargetOrigin origin = TargetOrigin.parse(uri.getScheme() + "://" + uri.getRawAuthority());
        HttpRequestData request = new RawHttpRequestParser().parse(requestRaw.getBytes(StandardCharsets.ISO_8859_1), origin);
        if (httpMode != null && !httpMode.isBlank()) request = request.withProtocol(HttpProtocol.parse(httpMode));
        return new PlannedRequest(payloadFamily, payload, payloadEncoding, request, controlRole != null && controlRole != com.bypassfuzzer.core.scan.ControlRole.NONE, com.bypassfuzzer.core.scan.ProbeIntent.STANDARD,"","",playbookId,controlRole);
    }
}
