package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.RateLimiter;
import com.bypassfuzzer.burp.core.payloads.PayloadLoader;
import com.bypassfuzzer.burp.core.payloads.UrlPayloadProcessor;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

public class PathAttack implements AttackStrategy {
    private final List<String> pathPayloads;

    public PathAttack(String targetUrl) {
        List<String> payloads;
        try {
            List<String> urlPayloads = PayloadLoader.loadPayloads("url_payloads.txt");
            UrlPayloadProcessor processor = new UrlPayloadProcessor(targetUrl);
            payloads = processor.generateUrlPayloads(urlPayloads);
        } catch (Exception e) {
            payloads = new ArrayList<>();
        }
        this.pathPayloads = payloads;
    }

    @Override
    public void execute(MontoyaApi api, HttpRequest baseRequest, String targetUrl, Consumer<AttackResult> resultCallback, BooleanSupplier shouldContinue, RateLimiter rateLimiter) {
        // Check if original request is just root path
        String originalPath = extractPath(targetUrl);
        try {
            api.logging().logToOutput("Path Attack: Checking path from URL '" + targetUrl + "' -> extracted path: '" + originalPath + "'");
        } catch (Exception e) {
            // Ignore
        }
        if ("/".equals(originalPath)) {
            try {
                api.logging().logToOutput("Path Attack: Skipped - original path is root '/' (path manipulation attacks are less effective on root paths - consider testing a deeper endpoint)");
            } catch (Exception e) {
                // Ignore
            }
            return;
        }

        try {
            api.logging().logToOutput("Starting Path Attack: " + pathPayloads.size() + " payloads");
        } catch (Exception e) {
            // API may be null, abort
            return;
        }

        int count = 0;
        for (String modifiedUrl : pathPayloads) {
            if (!shouldContinue.getAsBoolean()) {
                try {
                    api.logging().logToOutput("Path Attack stopped by user (" + count + " of " + pathPayloads.size() + " completed)");
                } catch (Exception e) {
                    // Ignore
                }
                break;
            }

            try {
                // Log progress every 50 requests to avoid spam
                if (count % 50 == 0 && pathPayloads.size() > 50) {
                    try {
                        api.logging().logToOutput("Path Attack progress: " + count + " of " + pathPayloads.size() + " requests sent");
                    } catch (Exception e) {
                        // Ignore
                    }
                }

                // Apply rate limiting
                if (rateLimiter != null) {
                    rateLimiter.waitBeforeRequest();
                }

                HttpRequest modifiedRequest = baseRequest.withPath(extractPath(modifiedUrl));
                HttpResponse response = api.http().sendRequest(modifiedRequest).response();
                resultCallback.accept(new AttackResult(getAttackType(), modifiedUrl, modifiedRequest, response));
                count++;
            } catch (NullPointerException e) {
                // API became null (extension unloaded), stop immediately
                break;
            } catch (Exception e) {
                try {
                    api.logging().logToError("Path attack error with URL: " + modifiedUrl + " - " + e.getMessage());
                } catch (Exception logError) {
                    // Ignore logging errors
                }
            }
        }

        try {
            api.logging().logToOutput("Path Attack completed: " + count + " results sent");
        } catch (Exception e) {
            // Ignore
        }
    }

    private String extractPath(String url) {
        try {
            int schemeEnd = url.indexOf("://");
            if (schemeEnd != -1) {
                int pathStart = url.indexOf('/', schemeEnd + 3);
                if (pathStart != -1) {
                    return url.substring(pathStart);
                }
            }
            return "/";
        } catch (Exception e) {
            return "/";
        }
    }

    @Override
    public String getAttackType() {
        return "Path";
    }
}
