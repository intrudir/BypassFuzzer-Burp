package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.core.ByteArray;
import com.bypassfuzzer.burp.core.RateLimiter;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.*;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

public class ProtocolAttack implements AttackStrategy {
    private static final List<String> HTTP_VERSIONS = Arrays.asList("HTTP/2", "HTTP/1.1", "HTTP/1.0", "HTTP/0.9");
    private static final int REQUEST_TIMEOUT_SECONDS = 5;

    @Override
    public void execute(MontoyaApi api, HttpRequest baseRequest, String targetUrl, Consumer<AttackResult> resultCallback, BooleanSupplier shouldContinue, RateLimiter rateLimiter) {
        try {
            api.logging().logToOutput("Starting Protocol Attack");
        } catch (Exception e) {
            return;
        }

        for (String version : HTTP_VERSIONS) {
            if (!shouldContinue.getAsBoolean()) {
                try {
                    api.logging().logToOutput("Protocol Attack stopped by user");
                } catch (Exception e) {}
                return;
            }

            try {
                api.logging().logToOutput("Testing protocol: " + version);
                HttpRequest modifiedRequest = buildRequestWithVersion(api, baseRequest, version);
                HttpResponse response = sendRequestWithTimeout(api, modifiedRequest, version, shouldContinue, rateLimiter);

                if (response != null) {
                    String payload = "Protocol: " + version;
                    resultCallback.accept(new AttackResult(getAttackType(), payload, modifiedRequest, response));
                    api.logging().logToOutput("Protocol " + version + " completed with status: " + response.statusCode());
                } else {
                    api.logging().logToOutput("Protocol " + version + " timed out after " + REQUEST_TIMEOUT_SECONDS + " seconds");
                }
            } catch (NullPointerException e) {
                return;
            } catch (Exception e) {
                try {
                    api.logging().logToError("Protocol attack error: " + version + " - " + e.getMessage());
                } catch (Exception logError) {}
            }
        }

        try {
            api.logging().logToOutput("Protocol Attack completed");
        } catch (Exception e) {}
    }

    private HttpRequest buildRequestWithVersion(MontoyaApi api, HttpRequest baseRequest, String newVersion) {
        try {
            ByteArray requestBytes = baseRequest.toByteArray();
            String rawRequest = requestBytes.toString();
            int firstLineEnd = rawRequest.indexOf("\r\n");
            if (firstLineEnd == -1) {
                firstLineEnd = rawRequest.indexOf("\n");
            }

            if (firstLineEnd > 0) {
                String requestLine = rawRequest.substring(0, firstLineEnd);
                String restOfRequest = rawRequest.substring(firstLineEnd);
                String newRequestLine = requestLine.replaceFirst("HTTP/[0-9.]+", newVersion);
                String newRawRequest = newRequestLine + restOfRequest;

                // Add appropriate headers based on version
                if (newVersion.equals("HTTP/1.0")) {
                    // For HTTP/1.0, ensure Connection: close header exists
                    if (!newRawRequest.toLowerCase().contains("connection:")) {
                        int headerInsertPos = newRawRequest.indexOf("\r\n") + 2;
                        if (headerInsertPos == 1) {
                            headerInsertPos = newRawRequest.indexOf("\n") + 1;
                        }
                        newRawRequest = newRawRequest.substring(0, headerInsertPos) +
                                       "Connection: close\r\n" +
                                       newRawRequest.substring(headerInsertPos);
                    }
                } else if (newVersion.equals("HTTP/2")) {
                    // HTTP/2 cleartext upgrade (h2c)
                    if (!newRawRequest.toLowerCase().contains("upgrade:")) {
                        int headerInsertPos = newRawRequest.indexOf("\r\n") + 2;
                        if (headerInsertPos == 1) {
                            headerInsertPos = newRawRequest.indexOf("\n") + 1;
                        }
                        newRawRequest = newRawRequest.substring(0, headerInsertPos) +
                                       "Upgrade: h2c\r\n" +
                                       "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n" +
                                       newRawRequest.substring(headerInsertPos);
                    }
                }

                try {
                    api.logging().logToOutput("Built " + newVersion + " request: " + newRequestLine);
                } catch (Exception e) {}
                return HttpRequest.httpRequest(baseRequest.httpService(), ByteArray.byteArray(newRawRequest));
            }
        } catch (Exception e) {
            try {
                api.logging().logToError("Failed to build " + newVersion + " request: " + e.getMessage());
            } catch (Exception logError) {}
        }

        return baseRequest;
    }

    private HttpResponse sendRequestWithTimeout(MontoyaApi api, HttpRequest request, String version, BooleanSupplier shouldContinue, RateLimiter rateLimiter) {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<HttpResponse> future = null;

        try {
            future = executor.submit(() -> {
                try {
                    return api.http().sendRequest(request).response();
                } catch (Exception e) {
                    return null;
                }
            });

            HttpResponse response = future.get(REQUEST_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            return response;
        } catch (TimeoutException e) {
            try {
                api.logging().logToOutput(version + " request TIMED OUT after " + REQUEST_TIMEOUT_SECONDS + " seconds");
            } catch (Exception logError) {}
            if (future != null) {
                future.cancel(true);
            }
            return null;
        } catch (InterruptedException e) {
            return null;
        } catch (Exception e) {
            return null;
        } finally {
            try {
                executor.shutdownNow();
                executor.awaitTermination(1, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                // Ignore
            }
        }
    }

    @Override
    public String getAttackType() {
        return "Protocol";
    }
}
