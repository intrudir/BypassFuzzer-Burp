package com.bypassfuzzer.burp.testsupport;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.core.http.RequestPathUtils;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Collections;

public final class HttpRequestTestFactory {

    private HttpRequestTestFactory() {
    }

    public static HttpRequest request(String path, String query, String method, String contentType, String body) {
        Map<String, String> headers = new LinkedHashMap<>();
        if (contentType != null) {
            headers.put("Content-Type", contentType);
        }
        return requestWithHeaders(path, query, method, headers, body);
    }

    public static HttpRequest requestWithHeaders(String path, String query, String method, Map<String, String> headers, String body) {
        ByteArray byteArray = byteArray(body.length());
        HttpService service = httpService();
        String pathWithQuery = query == null || query.isEmpty() ? path : path + "?" + query;
        String rawRequest = rawRequest(pathWithQuery, method, headers, body);

        return (HttpRequest) Proxy.newProxyInstance(
            HttpRequest.class.getClassLoader(),
            new Class<?>[]{HttpRequest.class},
            (proxy, invokedMethod, args) -> switch (invokedMethod.getName()) {
                case "httpService" -> service;
                case "path" -> pathWithQuery;
                case "pathWithoutQuery" -> RequestPathUtils.pathWithoutQuery(pathWithQuery);
                case "query" -> query;
                case "method" -> method;
                case "headerValue" -> headerValue(headers, (String) args[0]);
                case "hasHeader" -> headerValue(headers, (String) args[0]) != null;
                case "headers" -> headers(headers);
                case "bodyToString" -> body;
                case "body" -> byteArray;
                case "url" -> "https://example.com" + pathWithQuery;
                case "isInScope" -> true;
                case "withMethod" -> requestWithHeaders(path, query, (String) args[0], headers, body);
                case "withUpdatedHeader" -> requestWithHeaders(path, query, method, updatedHeaders(headers, (String) args[0], (String) args[1]), body);
                case "withAddedHeader" -> requestWithHeaders(path, query, method, addedHeader(headers, (String) args[0], (String) args[1]), body);
                case "withHeader" -> requestWithHeaders(path, query, method, updatedHeaders(headers, (String) args[0], (String) args[1]), body);
                case "withRemovedHeader" -> requestWithHeaders(path, query, method, removedHeader(headers, (String) args[0]), body);
                case "withBody" -> requestWithHeaders(path, query, method, headers, (String) args[0]);
                case "withPath" -> {
                    String updatedPath = (String) args[0];
                    yield requestWithHeaders(
                        RequestPathUtils.pathWithoutQuery(updatedPath),
                        RequestPathUtils.queryFromPath(updatedPath),
                        method,
                        headers,
                        body
                    );
                }
                case "toString" -> rawRequest;
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                default -> defaultValue(invokedMethod.getReturnType());
            }
        );
    }

    public static HttpRequest fromRawRequest(String rawRequest) {
        String normalized = rawRequest == null ? "" : rawRequest;
        String lineSeparator = normalized.contains("\r\n") ? "\r\n" : "\n";
        String separator = lineSeparator + lineSeparator;
        int split = normalized.indexOf(separator);
        String head = split >= 0 ? normalized.substring(0, split) : normalized;
        String body = split >= 0 ? normalized.substring(split + separator.length()) : "";
        String[] lines = head.split(java.util.regex.Pattern.quote(lineSeparator));
        String requestLine = lines.length == 0 ? "GET / HTTP/1.1" : lines[0];
        String[] parts = requestLine.split(" ", 3);
        String method = parts.length > 0 ? parts[0] : "GET";
        String pathWithQuery = parts.length > 1 ? parts[1] : "/";
        Map<String, String> headers = new LinkedHashMap<>();
        for (int i = 1; i < lines.length; i++) {
            int separatorIndex = lines[i].indexOf(':');
            if (separatorIndex <= 0) {
                continue;
            }
            headers.put(lines[i].substring(0, separatorIndex).trim(), lines[i].substring(separatorIndex + 1).trim());
        }
        return requestWithHeaders(
            RequestPathUtils.pathWithoutQuery(pathWithQuery),
            RequestPathUtils.queryFromPath(pathWithQuery),
            method,
            headers,
            body
        );
    }

    private static HttpService httpService() {
        return (HttpService) Proxy.newProxyInstance(
            HttpService.class.getClassLoader(),
            new Class<?>[]{HttpService.class},
            (proxy, invokedMethod, args) -> switch (invokedMethod.getName()) {
                case "host" -> "example.com";
                case "port" -> 443;
                case "secure" -> true;
                case "ipAddress" -> "example.com";
                case "toString" -> "https://example.com";
                default -> defaultValue(invokedMethod.getReturnType());
            }
        );
    }

    private static String rawRequest(String pathWithQuery, String method, Map<String, String> headers, String body) {
        StringBuilder request = new StringBuilder();
        request.append(method).append(" ").append(pathWithQuery).append(" HTTP/1.1\r\n");
        request.append("Host: example.com\r\n");
        for (Map.Entry<String, String> header : headers.entrySet()) {
            if ("Host".equalsIgnoreCase(header.getKey()) || header.getValue() == null) {
                continue;
            }
            request.append(header.getKey()).append(": ").append(header.getValue()).append("\r\n");
        }
        if (!body.isEmpty()) {
            request.append("Content-Length: ").append(body.length()).append("\r\n");
        }
        request.append("\r\n");
        request.append(body);
        return request.toString();
    }

    private static String headerValue(Map<String, String> headers, String name) {
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name)) {
                return entry.getValue();
            }
        }
        return null;
    }

    private static Map<String, String> updatedHeaders(Map<String, String> headers, String name, String value) {
        Map<String, String> updated = new LinkedHashMap<>(headers);
        String existingKey = null;
        for (String key : updated.keySet()) {
            if (key.equalsIgnoreCase(name)) {
                existingKey = key;
                break;
            }
        }
        if (existingKey != null) {
            updated.remove(existingKey);
        }
        updated.put(name, value);
        return updated;
    }

    private static Map<String, String> addedHeader(Map<String, String> headers, String name, String value) {
        Map<String, String> updated = new LinkedHashMap<>(headers);
        updated.put(name, value);
        return updated;
    }

    private static Map<String, String> removedHeader(Map<String, String> headers, String name) {
        Map<String, String> updated = new LinkedHashMap<>(headers);
        String existingKey = null;
        for (String key : updated.keySet()) {
            if (key.equalsIgnoreCase(name)) {
                existingKey = key;
                break;
            }
        }
        if (existingKey != null) {
            updated.remove(existingKey);
        }
        return updated;
    }

    private static List<HttpHeader> headers(Map<String, String> headers) {
        List<HttpHeader> result = new ArrayList<>();
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            result.add(header(entry.getKey(), entry.getValue()));
        }
        return result;
    }

    private static HttpHeader header(String name, String value) {
        return (HttpHeader) Proxy.newProxyInstance(
            HttpHeader.class.getClassLoader(),
            new Class<?>[]{HttpHeader.class},
            (proxy, invokedMethod, args) -> switch (invokedMethod.getName()) {
                case "name" -> name;
                case "value" -> value;
                case "toString" -> name + ": " + value;
                case "hashCode" -> java.util.Objects.hash(name, value);
                case "equals" -> proxy == args[0];
                default -> defaultValue(invokedMethod.getReturnType());
            }
        );
    }

    private static ByteArray byteArray(int length) {
        return (ByteArray) Proxy.newProxyInstance(
            ByteArray.class.getClassLoader(),
            new Class<?>[]{ByteArray.class},
            (proxy, invokedMethod, args) -> switch (invokedMethod.getName()) {
                case "length" -> length;
                case "iterator" -> Collections.<Byte>emptyIterator();
                case "toString" -> "";
                default -> defaultValue(invokedMethod.getReturnType());
            }
        );
    }

    private static Object defaultValue(Class<?> returnType) {
        if (returnType == boolean.class) {
            return false;
        }
        if (returnType == int.class) {
            return 0;
        }
        if (returnType == long.class) {
            return 0L;
        }
        if (returnType == short.class) {
            return (short) 0;
        }
        return null;
    }
}
