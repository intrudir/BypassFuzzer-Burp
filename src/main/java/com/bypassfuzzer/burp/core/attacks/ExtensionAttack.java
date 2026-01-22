package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.RateLimiter;
import com.bypassfuzzer.burp.core.payloads.PayloadLoader;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * Extension attack - appends file extensions to the URL path.
 * Tests if adding extensions like .json, .html, .php, etc. bypasses access controls.
 * Example: /admin -> /admin.json, /admin.html, etc.
 */
public class ExtensionAttack implements AttackStrategy {

    private final List<String> extensions;
    private final String targetUrl;

    public ExtensionAttack(String targetUrl) {
        this.targetUrl = targetUrl;
        this.extensions = PayloadLoader.loadPayloads("extension_payloads.txt");
    }

    @Override
    public void execute(MontoyaApi api, HttpRequest baseRequest, String targetUrl,
                       Consumer<AttackResult> resultCallback, BooleanSupplier shouldContinue,
                       RateLimiter rateLimiter) {

        // Check if original request is just root path
        String originalPath = extractPath(targetUrl);
        try {
            api.logging().logToOutput("Extension Attack: Checking path from URL '" + targetUrl + "' -> extracted path: '" + originalPath + "'");
        } catch (Exception e) {
            // Ignore
        }

        if ("/".equals(originalPath)) {
            try {
                api.logging().logToOutput("Extension Attack: Skipped - original path is root '/' (extension attacks are less effective on root paths - consider testing a deeper endpoint)");
            } catch (Exception e) {
                // Ignore
            }
            return;
        }

        try {
            api.logging().logToOutput("Starting Extension Attack: " + extensions.size() + " extensions");
        } catch (Exception e) {
            return;
        }

        int count = 0;
        for (String extension : extensions) {
            if (!shouldContinue.getAsBoolean()) {
                try {
                    api.logging().logToOutput("Extension Attack stopped by user (" + count + " of " + extensions.size() + " completed)");
                } catch (Exception e) {
                    // Ignore
                }
                break;
            }

            try {
                // Log progress every 20 requests
                if (count % 20 == 0 && count > 0) {
                    try {
                        api.logging().logToOutput("Extension Attack progress: " + count + " of " + extensions.size() + " requests sent");
                    } catch (Exception e) {
                        // Ignore
                    }
                }

                // Apply rate limiting
                if (rateLimiter != null) {
                    rateLimiter.waitBeforeRequest();
                }

                // Build modified path with extension
                String modifiedPath = buildPathWithExtension(targetUrl, extension);

                HttpRequest modifiedRequest = baseRequest.withPath(modifiedPath);
                HttpResponse response = api.http().sendRequest(modifiedRequest).response();

                // Create payload description for display
                String payloadDescription = originalPath + extension;

                resultCallback.accept(new AttackResult(getAttackType(), payloadDescription, modifiedRequest, response));
                count++;

            } catch (NullPointerException e) {
                // API became null (extension unloaded), stop immediately
                break;
            } catch (Exception e) {
                try {
                    api.logging().logToError("Extension attack error with extension: " + extension + " - " + e.getMessage());
                } catch (Exception logError) {
                    // Ignore
                }
            }
        }

        try {
            api.logging().logToOutput("Extension Attack completed: " + count + " results sent");
        } catch (Exception e) {
            // Ignore
        }
    }

    /**
     * Build a path with the extension appended.
     * Handles query strings correctly.
     */
    private String buildPathWithExtension(String url, String extension) {
        try {
            // Extract path and query from URL
            int schemeEnd = url.indexOf("://");
            if (schemeEnd != -1) {
                int pathStart = url.indexOf('/', schemeEnd + 3);
                if (pathStart != -1) {
                    String pathAndQuery = url.substring(pathStart);

                    // Check if there's a query string
                    int queryStart = pathAndQuery.indexOf('?');
                    if (queryStart != -1) {
                        // Insert extension before query string
                        String path = pathAndQuery.substring(0, queryStart);
                        String query = pathAndQuery.substring(queryStart);
                        return path + extension + query;
                    } else {
                        // No query string, just append extension
                        return pathAndQuery + extension;
                    }
                }
            }

            // Fallback: just append extension
            return "/" + extension;

        } catch (Exception e) {
            return "/" + extension;
        }
    }

    /**
     * Extract path from full URL (without query string).
     */
    private String extractPath(String url) {
        try {
            int schemeEnd = url.indexOf("://");
            if (schemeEnd != -1) {
                int pathStart = url.indexOf('/', schemeEnd + 3);
                if (pathStart != -1) {
                    String path = url.substring(pathStart);
                    // Return just the path without query
                    int queryStart = path.indexOf('?');
                    if (queryStart != -1) {
                        return path.substring(0, queryStart);
                    }
                    return path;
                }
            }
            return "/";
        } catch (Exception e) {
            return "/";
        }
    }

    @Override
    public String getAttackType() {
        return "Extension";
    }
}
