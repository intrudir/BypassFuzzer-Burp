package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.RateLimiter;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * Content-Type attack strategy.
 * Tests different content type encodings to find bypass vulnerabilities.
 * Converts between: URL-encoded, JSON, XML, and multipart/form-data.
 */
public class ContentTypeAttack implements AttackStrategy {

    @Override
    public void execute(MontoyaApi api, HttpRequest baseRequest, String targetUrl,
                       Consumer<AttackResult> resultCallback, BooleanSupplier shouldContinue,
                       RateLimiter rateLimiter) {

        try {
            api.logging().logToOutput("Starting Content-Type Attack");
        } catch (Exception e) {
            return;
        }

        int count = 0;

        // Extract parameters from request
        Map<String, String> params = extractParameters(baseRequest);

        if (params == null || params.isEmpty()) {
            try {
                api.logging().logToError("Content-Type Attack: Skipped - No parameters found to convert");
            } catch (Exception e) {
                // Ignore
            }
            return;
        }

        // If the method doesn't support a body (GET, HEAD, DELETE, etc.) but has parameters,
        // convert it to POST first, then test all content-type variations
        HttpRequest requestToModify = baseRequest;
        if (!supportsBody(baseRequest.method())) {
            try {
                api.logging().logToOutput("Content-Type Attack: Converting " + baseRequest.method() + " to POST to test content-type variations");
            } catch (Exception e) {
                // Ignore
            }
            requestToModify = baseRequest.withMethod("POST");
        }

        String currentContentType = requestToModify.headerValue("Content-Type");
        if (currentContentType == null) {
            currentContentType = "unknown";
        }

        try {
            api.logging().logToOutput("Content-Type Attack: Found " + params.size() + " parameters, current type: " + currentContentType);
        } catch (Exception e) {
            // Ignore
        }

        // Test 1: Convert to URL-encoded (if not already)
        if (!currentContentType.contains("application/x-www-form-urlencoded")) {
            if (!shouldContinue.getAsBoolean()) {
                logStop(api, count);
                return;
            }

            try {
                if (rateLimiter != null) {
                    rateLimiter.waitBeforeRequest();
                }

                HttpRequest request = convertToUrlEncoded(requestToModify, params);
                HttpResponse response = api.http().sendRequest(request).response();
                resultCallback.accept(new AttackResult(getAttackType(),
                    "Content-Type: URL-encoded", request, response));
                count++;
            } catch (Exception e) {
                logError(api, "Error converting to URL-encoded: " + e.getMessage());
            }
        }

        // Test 2: Convert to JSON
        if (!currentContentType.contains("application/json")) {
            if (!shouldContinue.getAsBoolean()) {
                logStop(api, count);
                return;
            }

            try {
                if (rateLimiter != null) {
                    rateLimiter.waitBeforeRequest();
                }

                HttpRequest request = convertToJson(requestToModify, params);
                HttpResponse response = api.http().sendRequest(request).response();
                resultCallback.accept(new AttackResult(getAttackType(),
                    "Content-Type: JSON", request, response));
                count++;
            } catch (Exception e) {
                logError(api, "Error converting to JSON: " + e.getMessage());
            }
        }

        // Test 3: Convert to XML
        if (!currentContentType.contains("application/xml") && !currentContentType.contains("text/xml")) {
            if (!shouldContinue.getAsBoolean()) {
                logStop(api, count);
                return;
            }

            try {
                if (rateLimiter != null) {
                    rateLimiter.waitBeforeRequest();
                }

                HttpRequest request = convertToXml(requestToModify, params);
                HttpResponse response = api.http().sendRequest(request).response();
                resultCallback.accept(new AttackResult(getAttackType(),
                    "Content-Type: XML", request, response));
                count++;
            } catch (Exception e) {
                logError(api, "Error converting to XML: " + e.getMessage());
            }
        }

        // Test 4: Convert to multipart/form-data
        if (!currentContentType.contains("multipart/form-data")) {
            if (!shouldContinue.getAsBoolean()) {
                logStop(api, count);
                return;
            }

            try {
                if (rateLimiter != null) {
                    rateLimiter.waitBeforeRequest();
                }

                HttpRequest request = convertToMultipart(requestToModify, params);
                HttpResponse response = api.http().sendRequest(request).response();
                resultCallback.accept(new AttackResult(getAttackType(),
                    "Content-Type: multipart/form-data", request, response));
                count++;
            } catch (Exception e) {
                logError(api, "Error converting to multipart: " + e.getMessage());
            }
        }

        try {
            api.logging().logToOutput("Content-Type Attack completed: " + count + " results sent");
        } catch (Exception e) {
            // Ignore
        }
    }

    /**
     * Check if HTTP method typically supports request body.
     */
    private boolean supportsBody(String method) {
        return method.equals("POST") || method.equals("PUT") || method.equals("PATCH");
    }

    /**
     * Extract parameters from request (from body or query string).
     */
    private Map<String, String> extractParameters(HttpRequest request) {
        Map<String, String> params = new LinkedHashMap<>();

        // Try to extract from body first
        String contentType = request.headerValue("Content-Type");
        if (contentType != null && request.body() != null && request.body().length() > 0) {
            if (contentType.contains("application/x-www-form-urlencoded")) {
                params.putAll(parseUrlEncoded(request.bodyToString()));
            } else if (contentType.contains("application/json")) {
                params.putAll(parseJson(request.bodyToString()));
            } else if (contentType.contains("application/xml") || contentType.contains("text/xml")) {
                params.putAll(parseXml(request.bodyToString()));
            } else if (contentType.contains("multipart/form-data")) {
                params.putAll(parseMultipart(request.bodyToString(), contentType));
            }
        }

        // If no body params, try query string
        if (params.isEmpty()) {
            String url = request.url();
            int queryStart = url.indexOf('?');
            if (queryStart != -1 && queryStart < url.length() - 1) {
                String query = url.substring(queryStart + 1);
                params.putAll(parseUrlEncoded(query));
            }
        }

        return params;
    }

    /**
     * Parse URL-encoded parameters.
     */
    private Map<String, String> parseUrlEncoded(String body) {
        Map<String, String> params = new LinkedHashMap<>();
        if (body == null || body.isEmpty()) {
            return params;
        }

        String[] pairs = body.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf('=');
            if (idx > 0) {
                try {
                    String key = URLDecoder.decode(pair.substring(0, idx), "UTF-8");
                    String value = idx < pair.length() - 1 ? URLDecoder.decode(pair.substring(idx + 1), "UTF-8") : "";
                    params.put(key, value);
                } catch (Exception e) {
                    // Skip malformed pairs
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
        if (body == null || body.isEmpty()) {
            return params;
        }

        try {
            // Simple JSON parsing for flat objects
            String json = body.trim();
            if (json.startsWith("{") && json.endsWith("}")) {
                json = json.substring(1, json.length() - 1);
                String[] pairs = json.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)"); // Split on commas not in quotes

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
     * Parse simple XML (basic key-value extraction).
     */
    private Map<String, String> parseXml(String body) {
        Map<String, String> params = new LinkedHashMap<>();
        if (body == null || body.isEmpty()) {
            return params;
        }

        try {
            // Simple XML parsing for flat structures
            String xml = body.trim();
            String[] tags = xml.split("<");
            for (String tag : tags) {
                if (tag.contains(">")) {
                    int endTag = tag.indexOf('>');
                    String tagName = tag.substring(0, endTag).trim();
                    if (!tagName.isEmpty() && !tagName.startsWith("/") && !tagName.startsWith("?") && !tagName.startsWith("!")) {
                        int closeStart = tag.indexOf("</");
                        if (closeStart > endTag) {
                            String value = tag.substring(endTag + 1, closeStart).trim();
                            params.put(tagName, value);
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
     * Parse multipart/form-data (basic extraction).
     */
    private Map<String, String> parseMultipart(String body, String contentType) {
        Map<String, String> params = new LinkedHashMap<>();
        if (body == null || body.isEmpty()) {
            return params;
        }

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
                        // Extract name
                        int nameStart = part.indexOf("name=\"") + 6;
                        if (nameStart > 5) {
                            int nameEnd = part.indexOf("\"", nameStart);
                            String name = part.substring(nameStart, nameEnd);

                            // Extract value (after double newline)
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
     * Convert parameters to URL-encoded format.
     */
    private HttpRequest convertToUrlEncoded(HttpRequest request, Map<String, String> params) {
        StringBuilder body = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (!first) body.append("&");
            body.append(urlEncode(entry.getKey())).append("=").append(urlEncode(entry.getValue()));
            first = false;
        }

        return request
            .withUpdatedHeader("Content-Type", "application/x-www-form-urlencoded")
            .withBody(body.toString());
    }

    /**
     * Convert parameters to JSON format.
     */
    private HttpRequest convertToJson(HttpRequest request, Map<String, String> params) {
        StringBuilder json = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (!first) json.append(",");
            json.append("\"").append(escapeJson(entry.getKey())).append("\":")
                .append("\"").append(escapeJson(entry.getValue())).append("\"");
            first = false;
        }
        json.append("}");

        return request
            .withUpdatedHeader("Content-Type", "application/json")
            .withBody(json.toString());
    }

    /**
     * Convert parameters to XML format.
     */
    private HttpRequest convertToXml(HttpRequest request, Map<String, String> params) {
        StringBuilder xml = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root>\n");
        for (Map.Entry<String, String> entry : params.entrySet()) {
            xml.append("  <").append(escapeXml(entry.getKey())).append(">")
               .append(escapeXml(entry.getValue()))
               .append("</").append(escapeXml(entry.getKey())).append(">\n");
        }
        xml.append("</root>");

        return request
            .withUpdatedHeader("Content-Type", "application/xml")
            .withBody(xml.toString());
    }

    /**
     * Convert parameters to multipart/form-data format.
     */
    private HttpRequest convertToMultipart(HttpRequest request, Map<String, String> params) {
        String boundary = "----WebKitFormBoundary" + UUID.randomUUID().toString().replaceAll("-", "").substring(0, 16);
        StringBuilder body = new StringBuilder();

        for (Map.Entry<String, String> entry : params.entrySet()) {
            body.append("--").append(boundary).append("\r\n");
            body.append("Content-Disposition: form-data; name=\"").append(entry.getKey()).append("\"\r\n\r\n");
            body.append(entry.getValue()).append("\r\n");
        }
        body.append("--").append(boundary).append("--\r\n");

        return request
            .withUpdatedHeader("Content-Type", "multipart/form-data; boundary=" + boundary)
            .withBody(body.toString());
    }

    /**
     * URL encode a string.
     */
    private String urlEncode(String value) {
        try {
            return java.net.URLEncoder.encode(value, "UTF-8");
        } catch (Exception e) {
            return value;
        }
    }

    /**
     * Escape string for JSON.
     */
    private String escapeJson(String value) {
        return value.replace("\\", "\\\\")
                   .replace("\"", "\\\"")
                   .replace("\n", "\\n")
                   .replace("\r", "\\r")
                   .replace("\t", "\\t");
    }

    /**
     * Escape string for XML.
     */
    private String escapeXml(String value) {
        return value.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&apos;");
    }

    private void logStop(MontoyaApi api, int count) {
        try {
            api.logging().logToOutput("Content-Type Attack stopped by user (" + count + " completed)");
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
        return "ContentType";
    }
}
