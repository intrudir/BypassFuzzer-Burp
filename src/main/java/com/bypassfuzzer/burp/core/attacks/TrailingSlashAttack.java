package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * Trailing slash attack.
 * Tests URL with and without a trailing slash to bypass access controls.
 */
public class TrailingSlashAttack implements AttackStrategy {

    private static final String ATTACK_TYPE = "TrailingSlash";

    @Override
    public String getAttackType() {
        return ATTACK_TYPE;
    }

    @Override
    public void execute(MontoyaApi api, HttpRequest originalRequest, String targetUrl,
                       Consumer<AttackResult> resultCallback, BooleanSupplier isRunning) {

        // Check if original request is just root path
        String originalPath = extractPath(targetUrl);
        try {
            api.logging().logToOutput("Trailing Slash Attack: Checking path from URL '" + targetUrl + "' -> extracted path: '" + originalPath + "'");
        } catch (Exception e) {
            // Ignore
        }
        if ("/".equals(originalPath)) {
            try {
                api.logging().logToOutput("Trailing Slash Attack: Skipped - original path is already root '/' (no variations possible)");
            } catch (Exception e) {
                // Ignore
            }
            return;
        }

        List<String> urlVariations = buildUrlVariations(targetUrl);

        try {
            api.logging().logToOutput("Starting Trailing Slash Attack: " + urlVariations.size() + " variations");
        } catch (Exception e) {
            return;
        }

        int count = 0;
        for (String urlVariation : urlVariations) {
            if (!isRunning.getAsBoolean()) {
                try {
                    api.logging().logToOutput("Trailing Slash Attack stopped by user (" + count + " of " + urlVariations.size() + " completed)");
                } catch (Exception e) {
                    // Ignore
                }
                break;
            }

            try {
                // Log progress every request (since there's only 1 variation typically)
                if (urlVariations.size() > 0) {
                    try {
                        api.logging().logToOutput("Trailing Slash Attack: Testing variation " + (count + 1) + " of " + urlVariations.size());
                    } catch (Exception e) {
                        // Ignore
                    }
                }

                // Create new request with modified URL
                HttpRequest modifiedRequest = originalRequest.withPath(urlVariation);

                // Send request
                HttpResponse response = api.http().sendRequest(modifiedRequest).response();

                // Create result
                AttackResult result = new AttackResult(
                    ATTACK_TYPE,
                    urlVariation,
                    modifiedRequest,
                    response
                );

                resultCallback.accept(result);
                count++;

            } catch (Exception e) {
                try {
                    api.logging().logToError("Error in trailing slash attack with URL '" + urlVariation + "': " + e.getMessage());
                } catch (Exception logError) {
                    // Ignore
                }
            }
        }

        try {
            api.logging().logToOutput("Trailing Slash Attack completed: " + count + " results sent");
        } catch (Exception e) {
            // Ignore
        }
    }

    /**
     * Build list of URL variations with/without trailing slash.
     */
    private List<String> buildUrlVariations(String url) {
        List<String> variations = new ArrayList<>();

        try {
            URI uri = new URI(url);
            String path = uri.getPath();
            String query = uri.getQuery();

            // Build query string part
            String queryPart = (query != null && !query.isEmpty()) ? "?" + query : "";

            // If path ends with slash, also try without
            if (path != null && path.endsWith("/")) {
                String pathWithoutSlash = path.substring(0, path.length() - 1);
                if (!pathWithoutSlash.isEmpty()) {
                    variations.add(pathWithoutSlash + queryPart);
                }
            }
            // If path doesn't end with slash, try with slash
            else if (path != null && !path.isEmpty()) {
                variations.add(path + "/" + queryPart);
            }

            // Always add the variation opposite to original
            // This handles edge cases and ensures we test both

        } catch (Exception e) {
            // If parsing fails, try simple string manipulation
            if (url.endsWith("/")) {
                // Remove trailing slash
                String withoutSlash = url.substring(0, url.length() - 1);
                if (!withoutSlash.isEmpty()) {
                    variations.add(withoutSlash);
                }
            } else {
                // Add trailing slash
                // But check if there's a query string first
                int queryIndex = url.indexOf('?');
                if (queryIndex != -1) {
                    // Insert slash before query string
                    String beforeQuery = url.substring(0, queryIndex);
                    String afterQuery = url.substring(queryIndex);
                    variations.add(beforeQuery + "/" + afterQuery);
                } else {
                    variations.add(url + "/");
                }
            }
        }

        return variations;
    }

    /**
     * Extract path from full URL.
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
}
