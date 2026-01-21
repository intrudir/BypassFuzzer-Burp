package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.RateLimiter;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * Debug parameter injection attack.
 * Appends debug/admin query parameters to bypass access controls.
 */
public class ParamAttack implements AttackStrategy {

    private static final String ATTACK_TYPE = "Param";

    @Override
    public String getAttackType() {
        return ATTACK_TYPE;
    }

    @Override
    public void execute(MontoyaApi api, HttpRequest originalRequest, String targetUrl,
                       Consumer<AttackResult> resultCallback, BooleanSupplier isRunning, RateLimiter rateLimiter) {

        List<String> paramPayloads = buildParamPayloads();

        // Extract just the path+query from the full URL
        String basePath = extractPathAndQuery(targetUrl);

        for (String param : paramPayloads) {
            if (!isRunning.getAsBoolean()) {
                break;
            }

            try {
                // Build modified path with parameter
                String modifiedPath = appendParameter(basePath, param);

                // Create new request with modified path
                // Apply rate limiting
                if (rateLimiter != null) {
                    rateLimiter.waitBeforeRequest();
                }
                HttpRequest modifiedRequest = originalRequest.withPath(modifiedPath);

                // Send request
                HttpResponse response = api.http().sendRequest(modifiedRequest).response();

                // Create result
                AttackResult result = new AttackResult(
                    ATTACK_TYPE,
                    param,
                    modifiedRequest,
                    response
                );

                resultCallback.accept(result);

            } catch (Exception e) {
                api.logging().logToError("Error in param attack with payload '" + param + "': " + e.getMessage());
            }
        }
    }

    /**
     * Build list of debug parameter payloads from resource file.
     */
    private List<String> buildParamPayloads() {
        List<String> basePayloads = loadPayloadsFromResource();

        // Add case variations
        List<String> allPayloads = new ArrayList<>(basePayloads);
        for (String payload : basePayloads) {
            // Generate 3 random case variations per payload
            for (int i = 0; i < 3; i++) {
                allPayloads.add(randomizeCase(payload));
            }
        }

        return allPayloads;
    }

    /**
     * Load parameter payloads from resource file.
     */
    private List<String> loadPayloadsFromResource() {
        List<String> payloads = new ArrayList<>();

        try (InputStream is = getClass().getResourceAsStream("/payloads/param_payloads.txt");
             BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {

            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) {
                    payloads.add(line);
                }
            }
        } catch (Exception e) {
            // Fallback to default payloads if resource file can't be loaded
            payloads.add("debug=true");
            payloads.add("debug=1");
            payloads.add("admin=true");
            payloads.add("admin=1");
        }

        return payloads;
    }

    /**
     * Randomize capitalization of characters in a string.
     * Creates variations like: admin=true -> Admin=true, aDmin=true, etc.
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

    /**
     * Extract path and query from a full URL.
     * Converts "https://example.com/path?query" to "/path?query"
     */
    private String extractPathAndQuery(String url) {
        try {
            int schemeEnd = url.indexOf("://");
            if (schemeEnd != -1) {
                int pathStart = url.indexOf('/', schemeEnd + 3);
                if (pathStart != -1) {
                    return url.substring(pathStart);
                }
            }
            // If no path found, return root
            return "/";
        } catch (Exception e) {
            return "/";
        }
    }

    /**
     * Append parameter to URL, handling existing query strings.
     */
    private String appendParameter(String url, String param) {
        // Check if URL already has query string
        if (url.contains("?")) {
            return url + "&" + param;
        } else {
            return url + "?" + param;
        }
    }
}
