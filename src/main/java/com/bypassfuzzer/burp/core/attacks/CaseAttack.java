package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * Case variation attack.
 * Generates random capitalizations of the URL path and query parameters.
 * Uses smart limits to avoid excessive variations on long URLs.
 */
public class CaseAttack implements AttackStrategy {

    private static final String ATTACK_TYPE = "Case";
    private static final int VARIATIONS_PER_COMPONENT = 5;
    private static final int MAX_TOTAL_VARIATIONS = 15;

    @Override
    public String getAttackType() {
        return ATTACK_TYPE;
    }

    @Override
    public void execute(MontoyaApi api, HttpRequest originalRequest, String targetUrl,
                       Consumer<AttackResult> resultCallback, BooleanSupplier isRunning) {

        List<String> urlVariations = buildUrlVariations(targetUrl);

        try {
            api.logging().logToOutput("Starting Case Attack: " + urlVariations.size() + " variations");
        } catch (Exception e) {
            return;
        }

        int count = 0;
        for (String urlVariation : urlVariations) {
            if (!isRunning.getAsBoolean()) {
                try {
                    api.logging().logToOutput("Case Attack stopped by user (" + count + " of " + urlVariations.size() + " completed)");
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
                    api.logging().logToError("Error in case attack with URL '" + urlVariation + "': " + e.getMessage());
                } catch (Exception logError) {
                    // Ignore
                }
            }
        }

        try {
            api.logging().logToOutput("Case Attack completed: " + count + " results sent");
        } catch (Exception e) {
            // Ignore
        }
    }

    /**
     * Build list of URL variations with randomized case.
     * Uses smart limits to avoid excessive variations on long URLs.
     */
    private List<String> buildUrlVariations(String url) {
        List<String> variations = new ArrayList<>();

        try {
            URI uri = new URI(url);
            String path = uri.getPath();
            String query = uri.getQuery();

            // Calculate smart variation counts based on URL complexity
            int pathLength = (path != null) ? path.length() : 0;
            int queryLength = (query != null) ? query.length() : 0;
            int totalLength = pathLength + queryLength;

            // Reduce variations for longer URLs
            int pathVariationCount;
            int queryVariationCount;

            if (totalLength > 100) {
                // Very long URL: minimal variations (2 each = max 6 total)
                pathVariationCount = 2;
                queryVariationCount = 2;
            } else if (totalLength > 50) {
                // Long URL: reduced variations (3 each = max 12 total)
                pathVariationCount = 3;
                queryVariationCount = 3;
            } else {
                // Normal URL: standard variations (5 each = max 36 total)
                pathVariationCount = VARIATIONS_PER_COMPONENT;
                queryVariationCount = VARIATIONS_PER_COMPONENT;
            }

            // Generate variations for path
            if (path != null && !path.isEmpty()) {
                List<String> pathVariations = generateCaseVariations(path, pathVariationCount);

                if (query != null && !query.isEmpty()) {
                    // Generate variations for query
                    List<String> queryVariations = generateCaseVariations(query, queryVariationCount);

                    // Combine path and query variations, but limit total
                    int combinationCount = 0;
                    for (String pathVar : pathVariations) {
                        for (String queryVar : queryVariations) {
                            if (combinationCount >= MAX_TOTAL_VARIATIONS) {
                                break;
                            }
                            variations.add(pathVar + "?" + queryVar);
                            combinationCount++;
                        }
                        if (combinationCount >= MAX_TOTAL_VARIATIONS) {
                            break;
                        }
                    }
                } else {
                    // Only path variations
                    variations.addAll(pathVariations);
                }
            } else if (query != null && !query.isEmpty()) {
                // Only query variations
                List<String> queryVariations = generateCaseVariations(query, queryVariationCount);
                for (String queryVar : queryVariations) {
                    variations.add("/?" + queryVar);
                }
            }

        } catch (Exception e) {
            // Fallback: if parsing fails, just add original URL
            variations.add(url);
        }

        return variations;
    }

    /**
     * Generate random case variations of a string.
     * Creates N random capitalizations of the input.
     */
    private List<String> generateCaseVariations(String input, int count) {
        List<String> variations = new ArrayList<>();

        // Add original
        variations.add(input);

        // Generate random variations
        for (int i = 0; i < count; i++) {
            variations.add(randomizeCase(input));
        }

        return variations;
    }

    /**
     * Randomize capitalization of characters in a string.
     */
    private String randomizeCase(String input) {
        Random random = new Random();
        StringBuilder result = new StringBuilder();

        for (char c : input.toCharArray()) {
            if (Character.isLetter(c)) {
                // Randomly choose upper or lower case
                if (random.nextBoolean()) {
                    result.append(Character.toUpperCase(c));
                } else {
                    result.append(Character.toLowerCase(c));
                }
            } else {
                result.append(c);
            }
        }

        return result.toString();
    }
}
