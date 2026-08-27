package com.bypassfuzzer.core.input;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Parses Postman Collection v2.0/v2.1 documents into method-aware sweep operations. */
public final class PostmanCollectionParser {

    public List<OpenApiOperation> parse(String source, String baseUrlOverride) {
        JsonObject root;
        try {
            root = JsonParser.parseString(source == null ? "" : source).getAsJsonObject();
        } catch (Exception e) {
            throw new IllegalArgumentException("File is not a valid Postman collection", e);
        }
        if (!isPostmanCollection(root)) {
            throw new IllegalArgumentException("File is not a Postman Collection v2 document");
        }

        String baseUrl = normalizeBaseUrl(baseUrlOverride);
        Map<String, String> variables = new LinkedHashMap<>();
        collectVariables(root.getAsJsonArray("variable"), variables);
        List<OpenApiOperation> operations = new ArrayList<>();
        Auth inheritedAuth = auth(root.getAsJsonObject("auth"), variables);
        walk(root.getAsJsonArray("item"), variables, baseUrl, inheritedAuth, operations);
        if (operations.isEmpty()) {
            throw new IllegalArgumentException("Postman collection contains no requests with usable HTTP(S) URLs");
        }
        return List.copyOf(operations);
    }

    public static boolean looksLikePostmanCollection(String source) {
        try {
            return isPostmanCollection(JsonParser.parseString(source == null ? "" : source).getAsJsonObject());
        } catch (Exception ignored) {
            return false;
        }
    }

    private void walk(JsonArray items, Map<String, String> inheritedVariables, String baseUrl, Auth inheritedAuth,
                      List<OpenApiOperation> operations) {
        if (items == null) return;
        for (JsonElement element : items) {
            if (!element.isJsonObject()) continue;
            JsonObject item = element.getAsJsonObject();
            if (booleanValue(item, "disabled")) continue;
            Map<String, String> variables = new LinkedHashMap<>(inheritedVariables);
            collectVariables(item.getAsJsonArray("variable"), variables);
            Auth itemAuth = item.has("auth") ? auth(item.getAsJsonObject("auth"), variables) : inheritedAuth;
            if (item.has("item") && item.get("item").isJsonArray()) {
                walk(item.getAsJsonArray("item"), variables, baseUrl, itemAuth, operations);
            }
            if (!item.has("request") || !item.get("request").isJsonObject()) continue;
            OpenApiOperation operation = request(item.getAsJsonObject("request"), variables, baseUrl, itemAuth);
            if (operation != null) operations.add(operation);
        }
    }

    private OpenApiOperation request(JsonObject request, Map<String, String> variables, String baseUrl,
                                     Auth inheritedAuth) {
        String method = stringValue(request, "method");
        if (method.isBlank()) method = "GET";
        String url = requestUrl(request.get("url"), variables);
        url = resolveUrl(url, baseUrl);
        if (url == null) return null;

        Map<String, String> headers = new LinkedHashMap<>();
        JsonArray headerArray = request.getAsJsonArray("header");
        if (headerArray != null) {
            for (JsonElement element : headerArray) {
                if (!element.isJsonObject()) continue;
                JsonObject header = element.getAsJsonObject();
                if (booleanValue(header, "disabled")) continue;
                String key = substitute(stringValue(header, "key"), variables);
                if (!key.isBlank()) headers.put(key, substitute(stringValue(header, "value"), variables));
            }
        }
        Auth requestAuth = request.has("auth") ? auth(request.getAsJsonObject("auth"), variables) : inheritedAuth;
        if (requestAuth != null && "query".equalsIgnoreCase(requestAuth.location())) {
            url += (url.contains("?") ? "&" : "?") + requestAuth.headerName() + "=" + requestAuth.headerValue();
        } else if (requestAuth != null && !requestAuth.headerName().isBlank()) {
            headers.putIfAbsent(requestAuth.headerName(), requestAuth.headerValue());
        }

        Body body = body(request.getAsJsonObject("body"), variables);
        if (!body.contentType().isBlank()) headers.putIfAbsent("Content-Type", body.contentType());
        return new OpenApiOperation(method.toUpperCase(Locale.ROOT), url, headers, body.value());
    }

    private String requestUrl(JsonElement urlElement, Map<String, String> variables) {
        if (urlElement == null || urlElement.isJsonNull()) return "";
        if (urlElement.isJsonPrimitive()) return substitute(urlElement.getAsString(), variables);
        if (!urlElement.isJsonObject()) return "";
        JsonObject url = urlElement.getAsJsonObject();
        Map<String, String> urlVariables = new LinkedHashMap<>(variables);
        collectVariables(url.getAsJsonArray("variable"), urlVariables);
        String raw = substitute(stringValue(url, "raw"), urlVariables);
        for (Map.Entry<String, String> variable : urlVariables.entrySet()) {
            raw = raw.replace(":" + variable.getKey(), variable.getValue());
        }
        if (!raw.isBlank()) {
            JsonArray query = url.getAsJsonArray("query");
            if (query == null) return raw;
            int fragment = raw.indexOf('#');
            String suffix = fragment >= 0 ? raw.substring(fragment) : "";
            String withoutFragment = fragment >= 0 ? raw.substring(0, fragment) : raw;
            int queryStart = withoutFragment.indexOf('?');
            StringBuilder rebuilt = new StringBuilder(queryStart >= 0
                ? withoutFragment.substring(0, queryStart) : withoutFragment);
            appendQuery(rebuilt, query, urlVariables);
            return rebuilt + suffix;
        }

        String protocol = substitute(stringValue(url, "protocol"), urlVariables);
        String host = join(url.getAsJsonArray("host"), ".", urlVariables);
        String path = join(url.getAsJsonArray("path"), "/", urlVariables);
        for (Map.Entry<String, String> variable : urlVariables.entrySet()) {
            path = path.replace(":" + variable.getKey(), variable.getValue());
        }
        StringBuilder built = new StringBuilder();
        if (!protocol.isBlank()) built.append(protocol).append("://");
        built.append(host);
        if (!path.isBlank()) built.append('/').append(path);
        appendQuery(built, url.getAsJsonArray("query"), urlVariables);
        return built.toString();
    }

    private Body body(JsonObject body, Map<String, String> variables) {
        if (body == null || booleanValue(body, "disabled")) return Body.EMPTY;
        String mode = stringValue(body, "mode");
        if ("raw".equals(mode)) {
            String contentType = "";
            JsonObject options = body.getAsJsonObject("options");
            JsonObject rawOptions = options == null ? null : options.getAsJsonObject("raw");
            String language = rawOptions == null ? "" : stringValue(rawOptions, "language");
            if ("json".equalsIgnoreCase(language)) contentType = "application/json";
            else if ("xml".equalsIgnoreCase(language)) contentType = "application/xml";
            else if ("text".equalsIgnoreCase(language)) contentType = "text/plain";
            return new Body(substitute(stringValue(body, "raw"), variables), contentType);
        }
        if ("urlencoded".equals(mode)) {
            return new Body(encodedPairs(body.getAsJsonArray("urlencoded"), variables),
                "application/x-www-form-urlencoded");
        }
        if ("formdata".equals(mode)) {
            String boundary = "----BypassFuzzerPostmanBoundary";
            StringBuilder value = new StringBuilder();
            JsonArray parts = body.getAsJsonArray("formdata");
            if (parts != null) for (JsonElement element : parts) {
                if (!element.isJsonObject()) continue;
                JsonObject part = element.getAsJsonObject();
                if (booleanValue(part, "disabled")) continue;
                String name = substitute(stringValue(part, "key"), variables);
                String type = stringValue(part, "type");
                value.append("--").append(boundary).append("\r\n")
                    .append("Content-Disposition: form-data; name=\"").append(name).append('"');
                if ("file".equals(type)) {
                    String source = sourceValue(part.get("src"));
                    String fileName = source.replace('\\', '/');
                    int slash = fileName.lastIndexOf('/');
                    if (slash >= 0) fileName = fileName.substring(slash + 1);
                    value.append("; filename=\"").append(fileName).append("\"\r\n")
                        .append("Content-Type: application/octet-stream\r\n\r\n");
                } else {
                    String contentType = stringValue(part, "contentType");
                    value.append("\r\n");
                    if (!contentType.isBlank()) value.append("Content-Type: ").append(contentType).append("\r\n");
                    value.append("\r\n").append(substitute(stringValue(part, "value"), variables));
                }
                value.append("\r\n");
            }
            value.append("--").append(boundary).append("--\r\n");
            return new Body(value.toString(), "multipart/form-data; boundary=" + boundary);
        }
        if ("graphql".equals(mode) && body.has("graphql") && body.get("graphql").isJsonObject()) {
            JsonObject graphql = body.getAsJsonObject("graphql");
            String query = substitute(stringValue(graphql, "query"), variables);
            String vars = substitute(stringValue(graphql, "variables"), variables);
            return new Body("{\"query\":" + jsonString(query) + ",\"variables\":"
                + (vars.isBlank() ? "{}" : vars) + "}", "application/json");
        }
        return Body.EMPTY;
    }

    private Auth auth(JsonObject auth, Map<String, String> variables) {
        if (auth == null) return null;
        String type = stringValue(auth, "type").toLowerCase(Locale.ROOT);
        if (type.isBlank() || "noauth".equals(type)) return null;
        Map<String, String> values = keyedValues(auth.getAsJsonArray(type), variables);
        return switch (type) {
            case "bearer" -> new Auth("Authorization", "Bearer " + values.getOrDefault("token", ""), "header");
            case "basic" -> {
                String credentials = values.getOrDefault("username", "") + ":" + values.getOrDefault("password", "");
                yield new Auth("Authorization", "Basic " + java.util.Base64.getEncoder()
                    .encodeToString(credentials.getBytes(StandardCharsets.UTF_8)), "header");
            }
            case "apikey" -> new Auth(values.getOrDefault("key", "X-API-Key"),
                values.getOrDefault("value", ""), values.getOrDefault("in", "header"));
            case "oauth2" -> new Auth("Authorization", "Bearer " + values.getOrDefault("accessToken", ""), "header");
            default -> null;
        };
    }

    private Map<String, String> keyedValues(JsonArray array, Map<String, String> variables) {
        Map<String, String> values = new LinkedHashMap<>();
        if (array == null) return values;
        for (JsonElement element : array) {
            if (!element.isJsonObject()) continue;
            JsonObject entry = element.getAsJsonObject();
            values.put(stringValue(entry, "key"), substitute(stringValue(entry, "value"), variables));
        }
        return values;
    }

    private static String sourceValue(JsonElement source) {
        if (source == null || source.isJsonNull()) return "file";
        if (source.isJsonPrimitive()) return source.getAsString();
        if (source.isJsonArray() && !source.getAsJsonArray().isEmpty()) {
            JsonElement first = source.getAsJsonArray().get(0);
            return first.isJsonPrimitive() ? first.getAsString() : "file";
        }
        return "file";
    }

    private String encodedPairs(JsonArray pairs, Map<String, String> variables) {
        if (pairs == null) return "";
        List<String> values = new ArrayList<>();
        for (JsonElement element : pairs) {
            if (!element.isJsonObject()) continue;
            JsonObject pair = element.getAsJsonObject();
            if (booleanValue(pair, "disabled")) continue;
            String key = substitute(stringValue(pair, "key"), variables);
            String value = substitute(stringValue(pair, "value"), variables);
            values.add(URLEncoder.encode(key, StandardCharsets.UTF_8) + "="
                + URLEncoder.encode(value, StandardCharsets.UTF_8));
        }
        return String.join("&", values);
    }

    private void appendQuery(StringBuilder target, JsonArray query, Map<String, String> variables) {
        if (query == null) return;
        List<String> pairs = new ArrayList<>();
        for (JsonElement element : query) {
            if (!element.isJsonObject()) continue;
            JsonObject entry = element.getAsJsonObject();
            if (booleanValue(entry, "disabled")) continue;
            String key = substitute(stringValue(entry, "key"), variables);
            String value = substitute(stringValue(entry, "value"), variables);
            pairs.add(key + (entry.has("value") ? "=" + value : ""));
        }
        if (!pairs.isEmpty()) target.append('?').append(String.join("&", pairs));
    }

    private String resolveUrl(String raw, String baseUrl) {
        String value = raw == null ? "" : raw.trim();
        if (value.matches("(?i)^https?://.*")) {
            try {
                URI uri = URI.create(value);
                return uri.getHost() == null ? null : value;
            } catch (Exception ignored) {
                return null;
            }
        }
        if (baseUrl.isBlank()) return null;
        String path = value.replaceFirst("^/", "");
        return baseUrl.endsWith("/") ? baseUrl + path : baseUrl + "/" + path;
    }

    private static String normalizeBaseUrl(String value) {
        String baseUrl = value == null ? "" : value.trim();
        if (baseUrl.isEmpty()) return "";
        try {
            URI uri = URI.create(baseUrl);
            if (("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()))
                && uri.getHost() != null) return baseUrl;
        } catch (Exception ignored) {
        }
        throw new IllegalArgumentException("Postman base URL must be an absolute HTTP or HTTPS URL");
    }

    private static void collectVariables(JsonArray array, Map<String, String> variables) {
        if (array == null) return;
        for (JsonElement element : array) {
            if (!element.isJsonObject()) continue;
            JsonObject variable = element.getAsJsonObject();
            if (booleanValue(variable, "disabled")) continue;
            String key = stringValue(variable, "key");
            if (!key.isBlank()) variables.put(key, stringValue(variable, "value"));
        }
    }

    private static String substitute(String value, Map<String, String> variables) {
        String result = value == null ? "" : value;
        for (int pass = 0; pass < 5; pass++) {
            String previous = result;
            for (Map.Entry<String, String> variable : variables.entrySet()) {
                result = result.replace("{{" + variable.getKey() + "}}", variable.getValue());
            }
            if (result.equals(previous)) break;
        }
        return result;
    }

    private static String join(JsonArray values, String delimiter, Map<String, String> variables) {
        if (values == null) return "";
        List<String> parts = new ArrayList<>();
        for (JsonElement value : values) if (value.isJsonPrimitive()) parts.add(substitute(value.getAsString(), variables));
        return String.join(delimiter, parts);
    }

    private static boolean isPostmanCollection(JsonObject root) {
        if (root == null || !root.has("info") || !root.get("info").isJsonObject()
            || !root.has("item") || !root.get("item").isJsonArray()) return false;
        String schema = stringValue(root.getAsJsonObject("info"), "schema");
        return schema.contains("schema.getpostman.com/json/collection/v2.");
    }

    private static String stringValue(JsonObject object, String key) {
        if (object == null || !object.has(key) || object.get(key).isJsonNull()
            || !object.get(key).isJsonPrimitive()) return "";
        return object.get(key).getAsString();
    }

    private static boolean booleanValue(JsonObject object, String key) {
        return object != null && object.has(key) && object.get(key).isJsonPrimitive()
            && object.get(key).getAsBoolean();
    }

    private static String jsonString(String value) {
        return new com.google.gson.Gson().toJson(value == null ? "" : value);
    }

    private record Body(String value, String contentType) {
        private static final Body EMPTY = new Body("", "");
    }

    private record Auth(String headerName, String headerValue, String location) {
    }
}
