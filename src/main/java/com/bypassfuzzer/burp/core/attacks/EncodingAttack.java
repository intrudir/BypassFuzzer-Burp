package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.RateLimiter;

import java.util.*;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * Encoding attack strategy.
 * Tests various encoding schemes on path and parameters to bypass security controls.
 * Uses smart limits to avoid combinatorial explosion on long strings.
 */
public class EncodingAttack implements AttackStrategy {

    // Encoding types
    private static final String[] ENCODING_TYPES = {
        "url",              // %61 for 'a'
        "double-url",       // %2561 for 'a'
        "triple-url",       // %25252561 for 'a'
        "unicode",          // %u0061 for 'a'
        "unicode-long",     // \u0061 for 'a'
        "unicode-overflow"  // %u4e61 for 'a' (0x4e61 % 256 = 0x61)
    };

    // Smart limits to prevent combinatorial explosion
    private static final int MAX_PATH_LENGTH = 50;  // Skip encoding attack if path is too long
    private static final int MAX_PARAM_LENGTH = 100;  // Skip individual param if too long (name or value)
    private static final int MAX_VARIATIONS_PER_STRING = 5;  // Max random variations per string

    @Override
    public void execute(MontoyaApi api, HttpRequest baseRequest, String targetUrl,
                       Consumer<AttackResult> resultCallback, BooleanSupplier shouldContinue,
                       RateLimiter rateLimiter) {

        try {
            api.logging().logToOutput("Starting Encoding Attack");
        } catch (Exception e) {
            return;
        }

        int count = 0;
        Random random = new Random();

        // Extract path from URL
        String path = extractPath(targetUrl);
        if ("/".equals(path)) {
            try {
                api.logging().logToError("Encoding Attack: Skipped - original path is root '/' (encoding attacks are less effective on root paths)");
            } catch (Exception e) {
                // Ignore
            }
            return;
        }

        // Check if path is too long
        if (path.length() > MAX_PATH_LENGTH) {
            try {
                api.logging().logToError("Encoding Attack: Skipped - path too long (" + path.length() + " chars, max " + MAX_PATH_LENGTH + ")");
            } catch (Exception e) {
                // Ignore
            }
            return;
        }

        try {
            api.logging().logToOutput("Encoding Attack: Testing " + ENCODING_TYPES.length + " encoding types on path and parameters");
        } catch (Exception e) {
            // Ignore
        }

        // Test 1: Encode random characters in path
        for (String encodingType : ENCODING_TYPES) {
            if (!shouldContinue.getAsBoolean()) {
                logStop(api, count);
                return;
            }

            // Generate multiple random variations for this encoding type
            for (int variation = 0; variation < MAX_VARIATIONS_PER_STRING; variation++) {
                if (!shouldContinue.getAsBoolean()) {
                    logStop(api, count);
                    return;
                }

                try {
                    if (rateLimiter != null) {
                        rateLimiter.waitBeforeRequest();
                    }

                    // Encode just the path portion, then re-add query string
                    String encodedPath = encodeRandomChars(path, encodingType, random);
                    String fullPath = buildPathWithQuery(baseRequest.url(), encodedPath);
                    HttpRequest modifiedRequest = baseRequest.withPath(fullPath);
                    HttpResponse response = api.http().sendRequest(modifiedRequest).response();

                    String payload = "Path " + encodingType + " #" + (variation + 1) + ": " + encodedPath;
                    resultCallback.accept(new AttackResult(getAttackType(), payload, modifiedRequest, response));
                    count++;
                } catch (NullPointerException e) {
                    return;
                } catch (Exception e) {
                    logError(api, "Encoding attack error: " + e.getMessage());
                }
            }
        }

        // Test 2: Encode parameter names and values
        Map<String, String> params = extractParameters(baseRequest);

        // Debug: log extracted parameters
        try {
            api.logging().logToOutput("Encoding Attack: Extracted " + params.size() + " parameters");
            int queryCount = 0;
            int bodyCount = 0;
            for (String key : params.keySet()) {
                if (key.startsWith("body_")) {
                    bodyCount++;
                } else {
                    queryCount++;
                }
            }
            api.logging().logToOutput("  Query params: " + queryCount + ", Body params: " + bodyCount);
        } catch (Exception e) {
            // Ignore
        }

        if (!params.isEmpty()) {
            for (String encodingType : ENCODING_TYPES) {
                if (!shouldContinue.getAsBoolean()) {
                    logStop(api, count);
                    return;
                }

                for (Map.Entry<String, String> param : params.entrySet()) {
                    String paramName = param.getKey();
                    String paramValue = param.getValue();

                    // Check if this is a body parameter (prefixed with "body_")
                    boolean isBodyParam = paramName.startsWith("body_");
                    String actualParamName = isBodyParam ? paramName.substring(5) : paramName;

                    // Skip if parameter name or value is too long
                    if (actualParamName.length() > MAX_PARAM_LENGTH || paramValue.length() > MAX_PARAM_LENGTH) {
                        try {
                            String skipReason = actualParamName.length() > MAX_PARAM_LENGTH
                                ? "name too long (" + actualParamName.length() + " chars)"
                                : "value too long (" + paramValue.length() + " chars)";
                            api.logging().logToOutput("  Skipping param '" + actualParamName + "': " + skipReason);
                        } catch (Exception e) {
                            // Ignore
                        }
                        continue;
                    }

                    if (!shouldContinue.getAsBoolean()) {
                        logStop(api, count);
                        return;
                    }

                    try {
                        if (rateLimiter != null) {
                            rateLimiter.waitBeforeRequest();
                        }

                        // Encode parameter name
                        String encodedName = encodeRandomChars(actualParamName, encodingType, random);
                        HttpRequest modifiedRequest = replaceParameterName(baseRequest, actualParamName, encodedName, paramValue, isBodyParam);
                        HttpResponse response = api.http().sendRequest(modifiedRequest).response();

                        String location = isBodyParam ? "body" : "query";
                        String payload = "Param name " + encodingType + " (" + location + "): " + actualParamName + " → " + encodedName;
                        resultCallback.accept(new AttackResult(getAttackType(), payload, modifiedRequest, response));
                        count++;
                    } catch (NullPointerException e) {
                        return;
                    } catch (Exception e) {
                        logError(api, "Encoding attack error on param name: " + e.getMessage());
                    }

                    if (!shouldContinue.getAsBoolean()) {
                        logStop(api, count);
                        return;
                    }

                    try {
                        if (rateLimiter != null) {
                            rateLimiter.waitBeforeRequest();
                        }

                        // Encode parameter value
                        String encodedValue = encodeRandomChars(paramValue, encodingType, random);
                        HttpRequest modifiedRequest = replaceParameterValue(baseRequest, actualParamName, encodedValue, isBodyParam);
                        HttpResponse response = api.http().sendRequest(modifiedRequest).response();

                        String location = isBodyParam ? "body" : "query";
                        String payload = "Param value " + encodingType + " (" + location + "): " + actualParamName + "=" + encodedValue;
                        resultCallback.accept(new AttackResult(getAttackType(), payload, modifiedRequest, response));
                        count++;
                    } catch (NullPointerException e) {
                        return;
                    } catch (Exception e) {
                        logError(api, "Encoding attack error on param value: " + e.getMessage());
                    }
                }
            }
        }

        try {
            api.logging().logToOutput("Encoding Attack completed: " + count + " results sent");
        } catch (Exception e) {
            // Ignore
        }
    }

    /**
     * Encode random characters in a string using the specified encoding type.
     * Encodes 30-50% of characters randomly.
     */
    private String encodeRandomChars(String input, String encodingType, Random random) {
        if (input == null || input.isEmpty()) {
            return input;
        }

        StringBuilder result = new StringBuilder();
        int encodeCount = Math.max(1, input.length() / 3); // Encode at least 1/3 of chars

        // Create set of random positions to encode
        Set<Integer> positionsToEncode = new HashSet<>();
        while (positionsToEncode.size() < encodeCount) {
            positionsToEncode.add(random.nextInt(input.length()));
        }

        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (positionsToEncode.contains(i) && isEncodable(c)) {
                result.append(encodeChar(c, encodingType));
            } else {
                result.append(c);
            }
        }

        return result.toString();
    }

    /**
     * Check if character should be encoded (alphanumeric and some special chars).
     */
    private boolean isEncodable(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
    }

    /**
     * Encode a single character using the specified encoding type.
     */
    private String encodeChar(char c, String encodingType) {
        switch (encodingType) {
            case "url":
                return String.format("%%%02X", (int) c);
            case "double-url":
                return String.format("%%25%02X", (int) c);
            case "triple-url":
                return String.format("%%2525%02X", (int) c);
            case "unicode":
                return String.format("%%u%04x", (int) c);
            case "unicode-long":
                return String.format("\\u%04x", (int) c);
            case "unicode-overflow":
                // Unicode overflow: generates codepoint that truncates to target char via modulus 256
                // Formula: target_char + (0x4e * 0x100) = overflow codepoint
                // Example: 'a' (0x61) -> 0x4e61, which overflows to 0x61 when stored as single byte
                // Range 0x4e00-0x4eff provides good bypass potential for blocklist filters
                int overflowCodepoint = (int) c + (0x4e * 0x100);
                return String.format("%%u%04x", overflowCodepoint);
            default:
                return String.valueOf(c);
        }
    }

    /**
     * Build full path with query string from original URL.
     * Takes the encoded path and appends the original query string if present.
     */
    private String buildPathWithQuery(String originalUrl, String encodedPath) {
        try {
            int queryStart = originalUrl.indexOf('?');
            if (queryStart != -1) {
                // Extract query string from original URL
                int schemeEnd = originalUrl.indexOf("://");
                if (schemeEnd != -1) {
                    int pathStart = originalUrl.indexOf('/', schemeEnd + 3);
                    if (pathStart != -1 && queryStart > pathStart) {
                        String queryString = originalUrl.substring(queryStart);
                        return encodedPath + queryString;
                    }
                }
            }
            return encodedPath;
        } catch (Exception e) {
            return encodedPath;
        }
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

    /**
     * Extract parameters from request (query string AND body, handles all content types).
     * Returns combined parameters from both locations.
     */
    private Map<String, String> extractParameters(HttpRequest request) {
        Map<String, String> params = new LinkedHashMap<>();

        // Extract query string parameters
        String url = request.url();
        int queryStart = url.indexOf('?');
        if (queryStart != -1 && queryStart < url.length() - 1) {
            String query = url.substring(queryStart + 1);
            String[] pairs = query.split("&");
            for (String pair : pairs) {
                int idx = pair.indexOf('=');
                if (idx > 0) {
                    String key = pair.substring(0, idx);
                    String value = idx < pair.length() - 1 ? pair.substring(idx + 1) : "";
                    params.put(key, value);
                }
            }
        }

        // ALSO extract body parameters (not "else if")
        if (request.body() != null && request.body().length() > 0) {
            String contentType = request.headerValue("Content-Type");
            String body = request.bodyToString();

            if (contentType != null) {
                if (contentType.contains("application/x-www-form-urlencoded")) {
                    // URL-encoded body
                    String[] pairs = body.split("&");
                    for (String pair : pairs) {
                        int idx = pair.indexOf('=');
                        if (idx > 0) {
                            String key = pair.substring(0, idx);
                            String value = idx < pair.length() - 1 ? pair.substring(idx + 1) : "";
                            // Prefix body params with "body_" to distinguish from query params with same name
                            params.put("body_" + key, value);
                        }
                    }
                } else if (contentType.contains("application/json")) {
                    // JSON body - simple key-value extraction
                    Map<String, String> bodyParams = parseJson(body);
                    for (Map.Entry<String, String> entry : bodyParams.entrySet()) {
                        params.put("body_" + entry.getKey(), entry.getValue());
                    }
                } else if (contentType.contains("application/xml") || contentType.contains("text/xml")) {
                    // XML body - simple key-value extraction
                    Map<String, String> bodyParams = parseXml(body);
                    for (Map.Entry<String, String> entry : bodyParams.entrySet()) {
                        params.put("body_" + entry.getKey(), entry.getValue());
                    }
                } else if (contentType.contains("multipart/form-data")) {
                    // Multipart form data
                    Map<String, String> bodyParams = parseMultipart(body, contentType);
                    for (Map.Entry<String, String> entry : bodyParams.entrySet()) {
                        params.put("body_" + entry.getKey(), entry.getValue());
                    }
                }
            }
        }

        return params;
    }

    /**
     * Parse simple JSON (basic key-value extraction).
     */
    private Map<String, String> parseJson(String body) {
        Map<String, String> params = new LinkedHashMap<>();
        try {
            String json = body.trim();
            if (json.startsWith("{") && json.endsWith("}")) {
                json = json.substring(1, json.length() - 1);
                String[] pairs = json.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
                for (String pair : pairs) {
                    String[] kv = pair.split(":", 2);
                    if (kv.length == 2) {
                        String key = kv[0].trim().replaceAll("^\"|\"$", "");
                        String value = kv[1].trim().replaceAll("^\"|\"$", "");
                        params.put(key, value);
                    }
                }
            }
        } catch (Exception e) {
            // Ignore parsing errors
        }
        return params;
    }

    /**
     * Parse XML (extracts all leaf node tag-value pairs, handling nested structures).
     * Uses regex to find all tags with text content (not nested tags).
     */
    private Map<String, String> parseXml(String body) {
        Map<String, String> params = new LinkedHashMap<>();
        try {
            String xml = body.trim();

            // Pattern to match: <tagName>textValue</tagName>
            // where textValue doesn't contain '<' (i.e., not nested tags)
            // Using DOTALL mode so [^<]+ can match across newlines
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(
                "<([a-zA-Z][a-zA-Z0-9_:-]*)>([^<]+)</\\1>",
                java.util.regex.Pattern.DOTALL
            );
            java.util.regex.Matcher matcher = pattern.matcher(xml);

            while (matcher.find()) {
                String tagName = matcher.group(1);
                String value = matcher.group(2).trim();

                // Only add if value is not empty
                if (!value.isEmpty()) {
                    params.put(tagName, value);
                }
            }
        } catch (Exception e) {
            // Ignore parsing errors
        }
        return params;
    }

    /**
     * Parse multipart/form-data (basic extraction).
     */
    private Map<String, String> parseMultipart(String body, String contentType) {
        Map<String, String> params = new LinkedHashMap<>();
        try {
            // Extract boundary
            String boundary = null;
            if (contentType.contains("boundary=")) {
                int boundaryStart = contentType.indexOf("boundary=") + 9;
                boundary = contentType.substring(boundaryStart).trim();
                if (boundary.contains(";")) {
                    boundary = boundary.substring(0, boundary.indexOf(";"));
                }
            }

            if (boundary != null) {
                String[] parts = body.split("--" + boundary);
                for (String part : parts) {
                    if (part.contains("Content-Disposition: form-data")) {
                        int nameStart = part.indexOf("name=\"") + 6;
                        if (nameStart > 5) {
                            int nameEnd = part.indexOf("\"", nameStart);
                            String name = part.substring(nameStart, nameEnd);
                            int valueStart = part.indexOf("\r\n\r\n");
                            if (valueStart > 0) {
                                String value = part.substring(valueStart + 4).trim();
                                params.put(name, value);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Ignore parsing errors
        }
        return params;
    }

    /**
     * Replace parameter name in request (handles query string and all body content types).
     * @param isBodyParam true if the parameter is in the body, false if in query string
     */
    private HttpRequest replaceParameterName(HttpRequest request, String oldName, String newName, String value, boolean isBodyParam) {
        String url = request.url();
        int queryStart = url.indexOf('?');

        if (!isBodyParam && queryStart != -1) {
            // Query string parameter
            String query = url.substring(queryStart + 1);
            String newQuery = query.replaceAll(
                "\\b" + java.util.regex.Pattern.quote(oldName) + "=",
                java.util.regex.Matcher.quoteReplacement(newName) + "="
            );
            String newUrl = url.substring(0, queryStart + 1) + newQuery;
            String newPath = extractPathFromUrl(newUrl);
            return request.withPath(newPath);
        } else if (isBodyParam && request.body() != null && request.body().length() > 0) {
            // Body parameter - handle different content types
            String contentType = request.headerValue("Content-Type");
            String body = request.bodyToString();
            String newBody = body;

            if (contentType != null) {
                if (contentType.contains("application/x-www-form-urlencoded")) {
                    // URL-encoded: param1=value1&param2=value2
                    newBody = body.replaceAll(
                        "\\b" + java.util.regex.Pattern.quote(oldName) + "=",
                        java.util.regex.Matcher.quoteReplacement(newName) + "="
                    );
                } else if (contentType.contains("application/json")) {
                    // JSON: {"param1": "value1", "param2": "value2"}
                    newBody = body.replaceAll(
                        "\"" + java.util.regex.Pattern.quote(oldName) + "\"\\s*:",
                        "\"" + java.util.regex.Matcher.quoteReplacement(newName) + "\":"
                    );
                } else if (contentType.contains("application/xml") || contentType.contains("text/xml")) {
                    // XML: <param1>value1</param1><param2>value2</param2>
                    newBody = body.replaceAll(
                        "<" + java.util.regex.Pattern.quote(oldName) + ">",
                        "<" + java.util.regex.Matcher.quoteReplacement(newName) + ">"
                    );
                    newBody = newBody.replaceAll(
                        "</" + java.util.regex.Pattern.quote(oldName) + ">",
                        "</" + java.util.regex.Matcher.quoteReplacement(newName) + ">"
                    );
                } else if (contentType.contains("multipart/form-data")) {
                    // Multipart: name="param1"
                    newBody = body.replaceAll(
                        "name=\"" + java.util.regex.Pattern.quote(oldName) + "\"",
                        "name=\"" + java.util.regex.Matcher.quoteReplacement(newName) + "\""
                    );
                }
            }

            return request.withBody(newBody);
        }

        return request;
    }

    /**
     * Replace parameter value in request (handles query string and all body content types).
     * @param isBodyParam true if the parameter is in the body, false if in query string
     */
    private HttpRequest replaceParameterValue(HttpRequest request, String paramName, String newValue, boolean isBodyParam) {
        String url = request.url();
        int queryStart = url.indexOf('?');

        if (!isBodyParam && queryStart != -1) {
            // Query string parameter
            String query = url.substring(queryStart + 1);
            String newQuery = query.replaceAll(
                "\\b" + java.util.regex.Pattern.quote(paramName) + "=[^&]*",
                java.util.regex.Matcher.quoteReplacement(paramName + "=" + newValue)
            );
            String newUrl = url.substring(0, queryStart + 1) + newQuery;
            String newPath = extractPathFromUrl(newUrl);
            return request.withPath(newPath);
        } else if (isBodyParam && request.body() != null && request.body().length() > 0) {
            // Body parameter - handle different content types
            String contentType = request.headerValue("Content-Type");
            String body = request.bodyToString();
            String newBody = body;

            if (contentType != null) {
                if (contentType.contains("application/x-www-form-urlencoded")) {
                    // URL-encoded: param1=value1&param2=value2
                    newBody = body.replaceAll(
                        "\\b" + java.util.regex.Pattern.quote(paramName) + "=[^&]*",
                        java.util.regex.Matcher.quoteReplacement(paramName + "=" + newValue)
                    );
                } else if (contentType.contains("application/json")) {
                    // JSON: {"param1": "value1", "param2": "value2"}
                    // Handle both string and non-string values
                    newBody = body.replaceAll(
                        "(\"" + java.util.regex.Pattern.quote(paramName) + "\"\\s*:\\s*)\"[^\"]*\"",
                        "$1\"" + java.util.regex.Matcher.quoteReplacement(newValue) + "\""
                    );
                    // Also handle non-quoted values (numbers, booleans)
                    newBody = newBody.replaceAll(
                        "(\"" + java.util.regex.Pattern.quote(paramName) + "\"\\s*:\\s*)[^,}\\]]+",
                        "$1\"" + java.util.regex.Matcher.quoteReplacement(newValue) + "\""
                    );
                } else if (contentType.contains("application/xml") || contentType.contains("text/xml")) {
                    // XML: <param1>value1</param1>
                    String pattern = "(<" + java.util.regex.Pattern.quote(paramName) + ">)[^<]*(</" + java.util.regex.Pattern.quote(paramName) + ">)";
                    String replacement = "$1" + java.util.regex.Matcher.quoteReplacement(newValue) + "$2";
                    newBody = body.replaceAll(pattern, replacement);
                } else if (contentType.contains("multipart/form-data")) {
                    // Multipart: Content-Disposition: form-data; name="param1"\r\n\r\nvalue1
                    newBody = body.replaceAll(
                        "(name=\"" + java.util.regex.Pattern.quote(paramName) + "\"\\r\\n\\r\\n)[^\\r\\n]*",
                        "$1" + java.util.regex.Matcher.quoteReplacement(newValue)
                    );
                }
            }

            return request.withBody(newBody);
        }

        return request;
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
            api.logging().logToOutput("Encoding Attack stopped by user (" + count + " completed)");
        } catch (Exception e) {
            // Ignore
        }
    }

    private void logError(MontoyaApi api, String message) {
        try {
            api.logging().logToError(message);
        } catch (Exception e) {
            // Ignore
        }
    }

    @Override
    public String getAttackType() {
        return "Encoding";
    }
}
