package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.RateLimiter;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * Cookie-based debug parameter injection attack.
 * Injects debug/admin parameters via the Cookie header to bypass access controls.
 *
 * Attack order:
 * 1. Fuzz existing cookies (preserve name case, try different values)
 * 2. Add new cookies (standard debug payloads)
 */
public class CookieParamAttack implements AttackStrategy {

    private static final String ATTACK_TYPE = "Cookie";
    private static final String EXISTING_COOKIE_TYPE = "Cookie (Existing)";

    // Values to try when fuzzing existing cookies
    private static final String[] FUZZ_VALUES = {
        "true", "1", "yes", "on", "admin", "root", "false", "0", "no", "off"
    };

    private final boolean fuzzExistingCookies;

    public CookieParamAttack(boolean fuzzExistingCookies) {
        this.fuzzExistingCookies = fuzzExistingCookies;
    }

    @Override
    public String getAttackType() {
        return ATTACK_TYPE;
    }

    @Override
    public void execute(MontoyaApi api, HttpRequest originalRequest, String targetUrl,
                       Consumer<AttackResult> resultCallback, BooleanSupplier isRunning, RateLimiter rateLimiter) {

        List<String> paramPayloads = buildParamPayloads();

        // Phase 1: Fuzz existing cookies first (if enabled)
        if (fuzzExistingCookies) {
            fuzzExistingCookies(api, originalRequest, resultCallback, isRunning, rateLimiter);
        }

        // Phase 2: Add new cookies
        executeNewCookieAttacks(api, originalRequest, paramPayloads, resultCallback, isRunning, rateLimiter);
    }

    /**
     * Fuzz existing cookies by trying different values while preserving cookie name case.
     */
    private void fuzzExistingCookies(MontoyaApi api, HttpRequest originalRequest,
                                     Consumer<AttackResult> resultCallback, BooleanSupplier isRunning,
                                     RateLimiter rateLimiter) {

        String existingCookie = originalRequest.headerValue("Cookie");
        if (existingCookie == null || existingCookie.isEmpty()) {
            return;
        }

        // Parse existing cookies
        Map<String, String> cookies = parseCookies(existingCookie);
        if (cookies.isEmpty()) {
            return;
        }

        for (Map.Entry<String, String> cookie : cookies.entrySet()) {
            String cookieName = cookie.getKey();

            // Try each fuzz value for this cookie
            for (String fuzzValue : FUZZ_VALUES) {
                if (!isRunning.getAsBoolean()) {
                    return;
                }

                try {
                    // Build new cookie string with modified value for this cookie
                    StringBuilder newCookie = new StringBuilder();
                    for (Map.Entry<String, String> c : cookies.entrySet()) {
                        if (newCookie.length() > 0) {
                            newCookie.append("; ");
                        }
                        if (c.getKey().equals(cookieName)) {
                            // Use fuzz value for this cookie
                            newCookie.append(cookieName).append("=").append(fuzzValue);
                        } else {
                            // Keep original value
                            newCookie.append(c.getKey()).append("=").append(c.getValue());
                        }
                    }

                    if (rateLimiter != null) {
                        rateLimiter.waitBeforeRequest();
                    }

                    HttpRequest modifiedRequest = originalRequest.withUpdatedHeader("Cookie", newCookie.toString());
                    HttpResponse response = api.http().sendRequest(modifiedRequest).response();

                    AttackResult result = new AttackResult(
                        EXISTING_COOKIE_TYPE,
                        cookieName + "=" + fuzzValue,
                        modifiedRequest,
                        response
                    );

                    resultCallback.accept(result);

                } catch (Exception e) {
                    api.logging().logToError("Error fuzzing existing cookie '" + cookieName + "': " + e.getMessage());
                }
            }
        }
    }

    /**
     * Execute cookie-based parameter attacks (adding new cookies).
     */
    private void executeNewCookieAttacks(MontoyaApi api, HttpRequest originalRequest,
                                         List<String> paramPayloads, Consumer<AttackResult> resultCallback,
                                         BooleanSupplier isRunning, RateLimiter rateLimiter) {

        String existingCookie = originalRequest.headerValue("Cookie");

        for (String param : paramPayloads) {
            if (!isRunning.getAsBoolean()) {
                break;
            }

            try {
                if (rateLimiter != null) {
                    rateLimiter.waitBeforeRequest();
                }

                HttpRequest modifiedRequest;
                if (existingCookie != null && !existingCookie.isEmpty()) {
                    modifiedRequest = originalRequest.withUpdatedHeader("Cookie", existingCookie + "; " + param);
                } else {
                    modifiedRequest = originalRequest.withAddedHeader("Cookie", param);
                }

                HttpResponse response = api.http().sendRequest(modifiedRequest).response();

                AttackResult result = new AttackResult(
                    ATTACK_TYPE,
                    param,
                    modifiedRequest,
                    response
                );

                resultCallback.accept(result);

            } catch (Exception e) {
                api.logging().logToError("Error in cookie param attack with payload '" + param + "': " + e.getMessage());
            }
        }
    }

    /**
     * Parse cookies from a Cookie header value.
     * Returns a LinkedHashMap to preserve order.
     */
    private Map<String, String> parseCookies(String cookieHeader) {
        Map<String, String> cookies = new LinkedHashMap<>();

        if (cookieHeader == null || cookieHeader.isEmpty()) {
            return cookies;
        }

        String[] pairs = cookieHeader.split(";");

        for (String pair : pairs) {
            pair = pair.trim();
            int eqIdx = pair.indexOf("=");
            if (eqIdx > 0) {
                String name = pair.substring(0, eqIdx).trim();
                String value = eqIdx < pair.length() - 1 ? pair.substring(eqIdx + 1).trim() : "";
                cookies.put(name, value);
            }
        }

        return cookies;
    }

    /**
     * Build list of debug parameter payloads from resource file.
     */
    private List<String> buildParamPayloads() {
        List<String> basePayloads = loadPayloadsFromResource();

        // Add case variations
        List<String> allPayloads = new ArrayList<>(basePayloads);
        for (String payload : basePayloads) {
            // First add systematic case variations (more likely to hit common patterns)
            allPayloads.add(capitalizeParamName(payload));  // admin=true -> Admin=true
            allPayloads.add(upperCaseParamName(payload));   // admin=true -> ADMIN=true

            // Then generate 3 random case variations per payload
            for (int i = 0; i < 3; i++) {
                allPayloads.add(randomizeCase(payload));
            }
        }

        return allPayloads;
    }

    /**
     * Capitalize first letter of parameter name (camelCase style).
     * admin=true -> Admin=true
     */
    private String capitalizeParamName(String payload) {
        int eqIdx = payload.indexOf('=');
        if (eqIdx <= 0) {
            return payload;
        }
        String name = payload.substring(0, eqIdx);
        String value = payload.substring(eqIdx);

        if (name.isEmpty()) {
            return payload;
        }

        return Character.toUpperCase(name.charAt(0)) + name.substring(1).toLowerCase() + value;
    }

    /**
     * Convert parameter name to all uppercase.
     * admin=true -> ADMIN=true
     */
    private String upperCaseParamName(String payload) {
        int eqIdx = payload.indexOf('=');
        if (eqIdx <= 0) {
            return payload;
        }
        String name = payload.substring(0, eqIdx);
        String value = payload.substring(eqIdx);

        return name.toUpperCase() + value;
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
     */
    private String randomizeCase(String input) {
        Random random = new Random();
        StringBuilder result = new StringBuilder();

        for (char c : input.toCharArray()) {
            if (Character.isLetter(c)) {
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
