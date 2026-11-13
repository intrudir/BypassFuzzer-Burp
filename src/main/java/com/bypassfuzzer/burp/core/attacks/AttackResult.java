package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * Represents the result of a single attack attempt.
 */
public class AttackResult implements com.bypassfuzzer.core.scan.ResultView {
    public record EvidenceMetadata(String playbookId, com.bypassfuzzer.core.scan.ControlRole controlRole,
        com.bypassfuzzer.core.scan.WildcardCalibration.Assessment calibration, HttpRequest fallbackRequest, HttpResponse fallbackResponse) {
        public static EvidenceMetadata empty() { return new EvidenceMetadata("", com.bypassfuzzer.core.scan.ControlRole.NONE,
            com.bypassfuzzer.core.scan.WildcardCalibration.Assessment.DISABLED, null, null); }
        public String annotation() { return calibration == com.bypassfuzzer.core.scan.WildcardCalibration.Assessment.MATCH ? "Possible fallback" :
            calibration == com.bypassfuzzer.core.scan.WildcardCalibration.Assessment.UNAVAILABLE ? "Calibration unavailable" : ""; }
    }
    private final EvidenceMetadata evidenceMetadata;
    public EvidenceMetadata getEvidenceMetadata() { return evidenceMetadata; }
    @Override public com.bypassfuzzer.core.scan.ControlRole getControlRole() { return evidenceMetadata.controlRole(); }
    public AttackResult withEvidenceMetadata(EvidenceMetadata metadata) {
        return new AttackResult(attackType,payload,targetLabel,payloadFamily,payloadEncoding,request,response,originalRequest,originalResponse,
            verificationRequest,verificationResponse,throttleRetryAttempt,statusCode,contentLength,contentType,timestamp,evidenceOnDisk,metadata);
    }
    private final String attackType;
    private final String payload;
    private final String targetLabel;
    private final String payloadFamily;
    private final String payloadEncoding;
    private final HttpRequest request;
    private final HttpResponse response;
    private final HttpRequest originalRequest;
    private final HttpResponse originalResponse;
    private final HttpRequest verificationRequest;
    private final HttpResponse verificationResponse;
    private final int statusCode;
    private final int contentLength;
    private final String contentType;
    private final long timestamp;
    private final int throttleRetryAttempt;
    private final boolean evidenceOnDisk;

    public AttackResult(String attackType, String payload, HttpRequest request, HttpResponse response) {
        this(attackType, payload, null, null, null, request, response, null);
    }

    public AttackResult(String attackType, String payload, String targetLabel, String payloadFamily,
                        String payloadEncoding, HttpRequest request, HttpResponse response) {
        this(attackType, payload, targetLabel, payloadFamily, payloadEncoding, request, response, null);
    }

    public AttackResult(String attackType, String payload, String targetLabel, String payloadFamily,
                        String payloadEncoding, HttpRequest request, HttpResponse response,
                        HttpResponse originalResponse) {
        this(attackType, payload, targetLabel, payloadFamily, payloadEncoding, request, response,
            null, originalResponse);
    }

    public AttackResult(String attackType, String payload, String targetLabel, String payloadFamily,
                        String payloadEncoding, HttpRequest request, HttpResponse response,
                        HttpRequest originalRequest, HttpResponse originalResponse) {
        this(attackType, payload, targetLabel, payloadFamily, payloadEncoding, request, response,
            originalRequest, originalResponse, null, null);
    }

    public AttackResult(String attackType, String payload, String targetLabel, String payloadFamily,
                        String payloadEncoding, HttpRequest request, HttpResponse response,
                        HttpRequest originalRequest, HttpResponse originalResponse,
                        HttpRequest verificationRequest, HttpResponse verificationResponse) {
        this(attackType, payload, targetLabel, payloadFamily, payloadEncoding, request, response,
            originalRequest, originalResponse, verificationRequest, verificationResponse, 0);
    }

    private AttackResult(String attackType, String payload, String targetLabel, String payloadFamily,
                         String payloadEncoding, HttpRequest request, HttpResponse response,
                         HttpRequest originalRequest, HttpResponse originalResponse,
                         HttpRequest verificationRequest, HttpResponse verificationResponse,
                         int throttleRetryAttempt) {
        this(attackType, payload, targetLabel, payloadFamily, payloadEncoding, request, response,
            originalRequest, originalResponse, verificationRequest, verificationResponse,
            throttleRetryAttempt,
            response != null ? response.statusCode() : 0,
            response != null ? response.body().length() : 0,
            response != null ? extractContentType(response) : "",
            System.currentTimeMillis(), false, EvidenceMetadata.empty());
    }

    private AttackResult(String attackType, String payload, String targetLabel, String payloadFamily,
                         String payloadEncoding, HttpRequest request, HttpResponse response,
                         HttpRequest originalRequest, HttpResponse originalResponse,
                         HttpRequest verificationRequest, HttpResponse verificationResponse,
                         int throttleRetryAttempt, int statusCode, int contentLength,
                         String contentType, long timestamp, boolean evidenceOnDisk, EvidenceMetadata metadata) {
        this.evidenceMetadata = metadata;
        this.attackType = attackType;
        this.payload = payload;
        this.targetLabel = targetLabel == null ? "" : targetLabel;
        this.payloadFamily = payloadFamily == null ? "" : payloadFamily;
        this.payloadEncoding = payloadEncoding == null ? "" : payloadEncoding;
        this.request = request;
        this.response = response;
        this.originalRequest = originalRequest;
        this.originalResponse = originalResponse;
        this.verificationRequest = verificationRequest;
        this.verificationResponse = verificationResponse;
        this.statusCode = statusCode;
        this.contentLength = contentLength;
        this.contentType = contentType;
        this.timestamp = timestamp;
        this.throttleRetryAttempt = Math.max(0, throttleRetryAttempt);
        this.evidenceOnDisk = evidenceOnDisk;
    }

    public static AttackResult throttleRetryOf(AttackResult original, HttpResponse response, int attempt) {
        return new AttackResult(
            original.attackType,
            original.payload,
            original.targetLabel,
            original.payloadFamily,
            original.payloadEncoding,
            original.request,
            response,
            original.originalRequest,
            original.originalResponse,
            original.verificationRequest,
            original.verificationResponse,
            attempt
        ).withEvidenceMetadata(original.evidenceMetadata);
    }

    /**
     * Moves the per-probe HTTP evidence behind Montoya's temp-file-backed message implementation.
     * Candidate baselines remain shared by identity across their results, while selecting or
     * exporting a row still exposes the complete request and response.
     */
    public AttackResult copyEvidenceToTempFile() {
        if (evidenceOnDisk) return this;
        return new AttackResult(
            attackType, payload, targetLabel, payloadFamily, payloadEncoding,
            tempFileCopy(request), tempFileCopy(response),
            originalRequest, originalResponse, verificationRequest, verificationResponse,
            throttleRetryAttempt, statusCode, contentLength, contentType, timestamp, true, evidenceMetadata);
    }

    public boolean isEvidenceOnDisk() {
        return evidenceOnDisk;
    }

    private static HttpRequest tempFileCopy(HttpRequest request) {
        if (request == null) return null;
        HttpRequest copy = request.copyToTempFile();
        return copy == null ? request : copy;
    }

    private static HttpResponse tempFileCopy(HttpResponse response) {
        if (response == null) return null;
        HttpResponse copy = response.copyToTempFile();
        return copy == null ? response : copy;
    }

    private static String extractContentType(HttpResponse response) {
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

    public String getTargetLabel() {
        return targetLabel;
    }

    public String getPayloadFamily() {
        return payloadFamily;
    }

    public String getPayloadEncoding() {
        return payloadEncoding;
    }

    /**
     * Returns the result signal. Coverage Sweep stores its signal in the
     * payload-encoding slot for compatibility with the shared results table.
     */
    public String getSignal() {
        return payloadEncoding;
    }

    public HttpRequest getRequest() {
        return request;
    }

    public HttpResponse getResponse() {
        return response;
    }

    public HttpRequest getOriginalRequest() {
        return originalRequest;
    }

    public HttpResponse getOriginalResponse() {
        return originalResponse;
    }

    public HttpRequest getVerificationRequest() {
        return verificationRequest;
    }

    public HttpResponse getVerificationResponse() {
        return verificationResponse;
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

    public int getThrottleRetryAttempt() {
        return throttleRetryAttempt;
    }

    @Override
    public String toString() {
        return String.format("[%s] %s -> %d (%d bytes)", attackType, payload, statusCode, contentLength);
    }
    public String getRequestHost() {
        if (getRequest() == null) return null;
        try { if (getRequest().httpService() != null) return getRequest().httpService().host(); }
        catch (Exception ignored) { }
        try { return java.net.URI.create(getRequest().url()).getHost(); }
        catch (Exception ignored) { return null; }
    }
    public String getResponseText() { return getResponse() == null ? null : String.valueOf(getResponse()); }
}
