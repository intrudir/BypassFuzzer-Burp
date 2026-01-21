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
}
