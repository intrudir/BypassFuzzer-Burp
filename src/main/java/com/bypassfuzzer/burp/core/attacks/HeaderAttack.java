package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.RateLimiter;
import com.bypassfuzzer.burp.core.payloads.HeaderPayloadProcessor;
import com.bypassfuzzer.burp.core.payloads.PayloadLoader;

import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

public class HeaderAttack implements AttackStrategy {
    private final HeaderPayloadProcessor processor;
    private final List<String> headerTemplates;
    private final List<String> ipPayloads;
    private final String targetUrl;
    private final String oobPayload;

    public HeaderAttack(String targetUrl, String oobPayload, boolean enableCollaborator) {
        this.targetUrl = targetUrl;
        this.oobPayload = oobPayload;
        this.processor = new HeaderPayloadProcessor(targetUrl, oobPayload);
        this.headerTemplates = PayloadLoader.loadPayloads("header_payload_templates.txt");
        this.ipPayloads = PayloadLoader.loadPayloads("ip_payloads.txt");
    }

    @Override
    public void execute(MontoyaApi api, HttpRequest baseRequest, String targetUrl, Consumer<AttackResult> resultCallback, BooleanSupplier shouldContinue, RateLimiter rateLimiter) {
        // Process header templates with dynamic Collaborator payload generation
        List<String> headerPayloads = processor.processHeaderTemplates(headerTemplates, ipPayloads, api);

        try {
            api.logging().logToOutput("Starting Header Attack: " + headerPayloads.size() + " total payloads");
        } catch (Exception e) {
            return;
        }

        int count = 0;

        for (String payload : headerPayloads) {
            if (!shouldContinue.getAsBoolean()) {
                try {
                    api.logging().logToOutput("Header Attack stopped by user (" + count + " of " + headerPayloads.size() + " completed)");
                } catch (Exception e) {
                    // Ignore
                }
                break;
            }

            // Log progress every 100 requests
            if (count % 100 == 0 && count > 0) {
                try {
                    api.logging().logToOutput("Header Attack progress: " + count + " of " + headerPayloads.size() + " requests sent");
                } catch (Exception e) {
                    // Ignore
                }
            }

            // Apply rate limiting
            if (rateLimiter != null) {
                rateLimiter.waitBeforeRequest();
            }

            try {
                String[] parts = payload.split(":", 2);
                if (parts.length != 2) {
                    continue;
                }

                String headerName = parts[0].trim();
                String headerValue = parts[1].trim();
                HttpRequest modifiedRequest;
                String displayPayload;

                // Check for PATH_SWAP marker
                if (headerValue.endsWith(" [PATH_SWAP]")) {
                    // Remove marker, swap path to /
                    headerValue = headerValue.replace(" [PATH_SWAP]", "");
                    modifiedRequest = baseRequest.withPath("/").withAddedHeader(headerName, headerValue);
                    displayPayload = headerName + ": " + headerValue + " (path→/)";
                } else {
                    modifiedRequest = baseRequest.withAddedHeader(headerName, headerValue);
                    displayPayload = payload;
                }

                HttpResponse response = api.http().sendRequest(modifiedRequest).response();
                resultCallback.accept(new AttackResult(getAttackType(), displayPayload, modifiedRequest, response));
                count++;
            } catch (NullPointerException e) {
                break;
            } catch (Exception e) {
                try {
                    api.logging().logToError("Header attack error with payload: " + payload + " - " + e.getMessage());
                } catch (Exception logError) {
                    // Ignore
                }
            }
        }

        try {
            api.logging().logToOutput("Header Attack completed: " + count + " results sent");
        } catch (Exception e) {
            // Ignore
        }
    }

    @Override
    public String getAttackType() {
        return "Header";
    }
}
