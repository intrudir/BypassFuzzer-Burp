package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.RateLimiter;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * Verb/Method attack strategy.
 * Tests different HTTP methods and method override headers.
 * For POST/PUT/PATCH, also tests parameter location variations (query vs body).
 */
public class VerbAttack implements AttackStrategy {
    private static final List<String> HTTP_METHODS = Arrays.asList(
        "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE",
        "PATCH"
    );

    private static final List<String> OVERRIDE_HEADERS = Arrays.asList(
        "X-HTTP-Method-Override",
        "X-HTTP-Method",
        "X-Method-Override"
    );

    // Methods that typically support request bodies
    private static final List<String> BODY_METHODS = Arrays.asList("POST", "PUT", "PATCH");

    @Override
    public void execute(MontoyaApi api, HttpRequest baseRequest, String targetUrl, Consumer<AttackResult> resultCallback, BooleanSupplier shouldContinue, RateLimiter rateLimiter) {
        try {
            api.logging().logToOutput("Starting Verb Attack");
        } catch (Exception e) {
            return;
        }

        int count = 0;

        // Test 1: Simple method changes
        for (String method : HTTP_METHODS) {
            if (!shouldContinue.getAsBoolean()) {
                logStop(api, count);
                return;
            }

            try {
                if (rateLimiter != null) {
                    rateLimiter.waitBeforeRequest();
                }

                HttpRequest modifiedRequest = createMethodRequest(baseRequest, method);
                HttpResponse response = api.http().sendRequest(modifiedRequest).response();
                resultCallback.accept(new AttackResult(getAttackType(), "Method: " + method, modifiedRequest, response));
                count++;
            } catch (NullPointerException e) {
                return;
            } catch (Exception e) {
                logError(api, "Verb attack error with method " + method + ": " + e.getMessage());
            }
        }

        // Test 2: Method override headers
        for (String header : OVERRIDE_HEADERS) {
            for (String method : HTTP_METHODS) {
                if (!shouldContinue.getAsBoolean()) {
                    logStop(api, count);
                    return;
                }

                try {
                    if (rateLimiter != null) {
                        rateLimiter.waitBeforeRequest();
                    }
                    HttpRequest modifiedRequest = baseRequest.withAddedHeader(header, method);
                    HttpResponse response = api.http().sendRequest(modifiedRequest).response();
                    String payload = header + ": " + method;
                    resultCallback.accept(new AttackResult(getAttackType(), payload, modifiedRequest, response));
                    count++;
                } catch (NullPointerException e) {
                    return;
                } catch (Exception e) {
                    logError(api, "Verb attack error with override " + header + "/" + method + ": " + e.getMessage());
                }
            }
        }

        // Test 3: Method combinations (e.g., POST with override to GET)
        for (String baseMethod : Arrays.asList("POST", "PUT")) {
            for (String header : OVERRIDE_HEADERS) {
                for (String overrideMethod : Arrays.asList("GET", "DELETE", "PATCH")) {
                    if (!shouldContinue.getAsBoolean()) {
                        logStop(api, count);
                        return;
                    }

                    try {
                        if (rateLimiter != null) {
                            rateLimiter.waitBeforeRequest();
                        }
                        HttpRequest modifiedRequest = baseRequest
                            .withMethod(baseMethod)
                            .withAddedHeader(header, overrideMethod);
                        HttpResponse response = api.http().sendRequest(modifiedRequest).response();
                        String payload = baseMethod + " + " + header + ": " + overrideMethod;
                        resultCallback.accept(new AttackResult(getAttackType(), payload, modifiedRequest, response));
                        count++;
                    } catch (NullPointerException e) {
                        return;
                    } catch (Exception e) {
                        logError(api, "Verb attack error: " + e.getMessage());
                    }
                }
            }
        }

        // Test 4: Parameter location variations for POST/PUT/PATCH
        count += testParameterVariations(api, baseRequest, resultCallback, shouldContinue, rateLimiter);

        try {
            api.logging().logToOutput("Verb Attack completed: " + count + " results sent");
        } catch (Exception e) {}
    }

    /**
     * Create a request with the specified method, handling parameter placement correctly.
     */
    private HttpRequest createMethodRequest(HttpRequest baseRequest, String method) {
        // If changing TO a body method (POST/PUT/PATCH), keep parameters where they are
        if (BODY_METHODS.contains(method)) {
            return baseRequest.withMethod(method);
        }

        // If changing FROM a body method TO GET/HEAD/DELETE, move body params to query string
        if (BODY_METHODS.contains(baseRequest.method()) &&
            (method.equals("GET") || method.equals("HEAD") || method.equals("DELETE"))) {

            String bodyParams = extractBodyParams(baseRequest);
            if (bodyParams != null && !bodyParams.isEmpty()) {
                return moveBodyToQuery(baseRequest, method, bodyParams);
            }
        }

        return baseRequest.withMethod(method);
    }

    /**
     * Test parameter location variations for POST/PUT/PATCH methods.
     * Tests:
     * 1. Original location (preserve)
     * 2. If params in query: also send in body, and in both
     * 3. If params in body: also send in query, and in both
     */
    private int testParameterVariations(MontoyaApi api, HttpRequest baseRequest,
                                       Consumer<AttackResult> resultCallback,
                                       BooleanSupplier shouldContinue,
                                       RateLimiter rateLimiter) {
        int count = 0;

        // Only test variations for methods that support bodies
        for (String method : Arrays.asList("POST", "PUT", "PATCH")) {
            if (!shouldContinue.getAsBoolean()) {
                return count;
            }

            String queryParams = extractQueryParams(baseRequest);
            String bodyParams = extractBodyParams(baseRequest);

            // Skip if no parameters to test
            if ((queryParams == null || queryParams.isEmpty()) &&
                (bodyParams == null || bodyParams.isEmpty())) {
                continue;
            }

            // Variation 1: If params in query, move them to body
            if (queryParams != null && !queryParams.isEmpty()) {
                if (!shouldContinue.getAsBoolean()) return count;

                try {
                    if (rateLimiter != null) {
                        rateLimiter.waitBeforeRequest();
                    }

                    HttpRequest request = moveQueryToBody(baseRequest, method, queryParams);
                    HttpResponse response = api.http().sendRequest(request).response();
                    resultCallback.accept(new AttackResult(getAttackType(),
                        method + " (params query→body)", request, response));
                    count++;
                } catch (Exception e) {
                    logError(api, "Error testing query→body: " + e.getMessage());
                }
            }

            // Variation 2: If params in body, move them to query
            if (bodyParams != null && !bodyParams.isEmpty()) {
                if (!shouldContinue.getAsBoolean()) return count;

                try {
                    if (rateLimiter != null) {
                        rateLimiter.waitBeforeRequest();
                    }

                    HttpRequest request = moveBodyToQuery(baseRequest, method, bodyParams);
                    HttpResponse response = api.http().sendRequest(request).response();
                    resultCallback.accept(new AttackResult(getAttackType(),
                        method + " (params body→query)", request, response));
                    count++;
                } catch (Exception e) {
                    logError(api, "Error testing body→query: " + e.getMessage());
                }
            }

            // Variation 3: Params in both query and body
            if ((queryParams != null && !queryParams.isEmpty()) ||
                (bodyParams != null && !bodyParams.isEmpty())) {
                if (!shouldContinue.getAsBoolean()) return count;

                try {
                    if (rateLimiter != null) {
                        rateLimiter.waitBeforeRequest();
                    }

                    String params = queryParams != null ? queryParams : bodyParams;
                    HttpRequest request = putParamsInBoth(baseRequest, method, params);
                    HttpResponse response = api.http().sendRequest(request).response();
                    resultCallback.accept(new AttackResult(getAttackType(),
                        method + " (params in query+body)", request, response));
                    count++;
                } catch (Exception e) {
                    logError(api, "Error testing params in both: " + e.getMessage());
                }
            }
        }

        return count;
    }

    /**
     * Extract query string parameters from request.
     */
    private String extractQueryParams(HttpRequest request) {
        try {
            String url = request.url();
            int queryStart = url.indexOf('?');
            if (queryStart != -1 && queryStart < url.length() - 1) {
                return url.substring(queryStart + 1);
            }
        } catch (Exception e) {
            // Ignore
        }
        return null;
    }

    /**
     * Extract body parameters from request (assumes form-encoded).
     */
    private String extractBodyParams(HttpRequest request) {
        try {
            if (request.body() != null && request.body().length() > 0) {
                String contentType = request.headerValue("Content-Type");
                if (contentType != null && contentType.contains("application/x-www-form-urlencoded")) {
                    return request.bodyToString();
                }
            }
        } catch (Exception e) {
            // Ignore
        }
        return null;
    }

    /**
     * Move query parameters to request body.
     */
    private HttpRequest moveQueryToBody(HttpRequest request, String method, String params) {
        // Remove query string from URL
        String url = request.url();
        int queryStart = url.indexOf('?');
        if (queryStart != -1) {
            url = url.substring(0, queryStart);
        }

        return request
            .withMethod(method)
            .withUpdatedHeader("Content-Type", "application/x-www-form-urlencoded")
            .withBody(params)
            .withPath(extractPathFromUrl(url));
    }

    /**
     * Move body parameters to query string.
     */
    private HttpRequest moveBodyToQuery(HttpRequest request, String method, String params) {
        String url = request.url();
        int queryStart = url.indexOf('?');
        String baseUrl = queryStart != -1 ? url.substring(0, queryStart) : url;

        String newUrl = baseUrl + "?" + params;
        String path = extractPathFromUrl(newUrl);

        return request
            .withMethod(method)
            .withPath(path)
            .withBody(""); // Remove body
    }

    /**
     * Put parameters in both query string and body.
     */
    private HttpRequest putParamsInBoth(HttpRequest request, String method, String params) {
        String url = request.url();
        int queryStart = url.indexOf('?');
        String baseUrl = queryStart != -1 ? url.substring(0, queryStart) : url;

        String newUrl = baseUrl + "?" + params;
        String path = extractPathFromUrl(newUrl);

        return request
            .withMethod(method)
            .withPath(path)
            .withUpdatedHeader("Content-Type", "application/x-www-form-urlencoded")
            .withBody(params);
    }

    /**
     * Extract path from full URL.
     */
    private String extractPathFromUrl(String url) {
        try {
            int schemeEnd = url.indexOf("://");
            if (schemeEnd != -1) {
                int pathStart = url.indexOf('/', schemeEnd + 3);
                if (pathStart != -1) {
                    return url.substring(pathStart);
                }
            }
        } catch (Exception e) {
            // Ignore
        }
        return "/";
    }

    private void logStop(MontoyaApi api, int count) {
        try {
            api.logging().logToOutput("Verb Attack stopped by user (" + count + " completed)");
        } catch (Exception e) {}
    }

    private void logError(MontoyaApi api, String message) {
        try {
            api.logging().logToError(message);
        } catch (Exception e) {}
    }

    @Override
    public String getAttackType() {
        return "Verb";
    }
}
