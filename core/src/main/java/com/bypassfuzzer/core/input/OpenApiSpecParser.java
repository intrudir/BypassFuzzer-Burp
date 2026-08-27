package com.bypassfuzzer.core.input;

import com.google.gson.Gson;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class OpenApiSpecParser {

    private static final Set<String> METHODS = Set.of("get", "head", "post", "put", "patch", "delete", "options", "trace");
    private final Gson gson = new Gson();

    public List<OpenApiOperation> parse(String source, String fileName) {
        return parse(source, fileName, "");
    }

    public List<OpenApiOperation> parse(String source, String fileName, String baseUrlOverride) {
        return parse(source, fileName, baseUrlOverride, "");
    }

    public List<OpenApiOperation> parse(String source, String fileName, String baseUrlOverride,
                                 String sourceUrl) {
        if (source != null && !source.isEmpty() && source.charAt(0) == '\ufeff') {
            source = source.substring(1);
        }
        source = removeYamlForbiddenCharacters(source);
        if (baseUrlOverride != null && !baseUrlOverride.isBlank() && !absoluteHttpUrl(baseUrlOverride)) {
            throw new IllegalArgumentException("OpenAPI base URL must be an absolute HTTP or HTTPS URL");
        }
        Object loaded = isJson(source, fileName)
            ? gson.fromJson(source, Object.class)
            : new Yaml(new SafeConstructor(new LoaderOptions())).load(source);
        Map<String, Object> root = map(loaded);
        if (root.isEmpty() || (!root.containsKey("openapi") && !root.containsKey("swagger"))) {
            throw new IllegalArgumentException("File is not an OpenAPI or Swagger specification");
        }

        Map<String, Object> paths = map(root.get("paths"));
        List<OpenApiOperation> operations = new ArrayList<>();
        for (Map.Entry<String, Object> pathEntry : paths.entrySet()) {
            Map<String, Object> pathItem = map(resolve(root, pathEntry.getValue()));
            for (String method : METHODS) {
                Map<String, Object> operation = map(resolve(root, pathItem.get(method)));
                if (operation.isEmpty()) continue;

                List<Map<String, Object>> parameters = combinedParameters(root,
                    pathItem.get("parameters"), operation.get("parameters"));
                RequestParts parts = requestParts(root, pathEntry.getKey(), parameters);
                BodyParts bodyParts = requestBody(root, operation, parameters);
                for (String server : servers(root, pathItem, operation, baseUrlOverride, sourceUrl)) {
                    String url = combine(server, parts.pathAndQuery());
                    if (url != null) {
                        operations.add(new OpenApiOperation(method.toUpperCase(Locale.ROOT), url,
                            merge(parts.headers(), bodyParts.headers()), bodyParts.body()));
                    }
                }
            }
        }
        if (operations.isEmpty()) {
            throw new IllegalArgumentException("OpenAPI specification contains no operations with an absolute HTTP(S) server URL");
        }
        return List.copyOf(operations);
    }

    private String removeYamlForbiddenCharacters(String source) {
        if (source == null || source.isEmpty()) return source;
        StringBuilder cleaned = null;
        for (int offset = 0; offset < source.length();) {
            int codePoint = source.codePointAt(offset);
            int width = Character.charCount(codePoint);
            if (!yamlCharacterAllowed(codePoint)) {
                if (cleaned == null) {
                    cleaned = new StringBuilder(source.length());
                    cleaned.append(source, 0, offset);
                }
            } else if (cleaned != null) {
                cleaned.appendCodePoint(codePoint);
            }
            offset += width;
        }
        return cleaned == null ? source : cleaned.toString();
    }

    private boolean yamlCharacterAllowed(int codePoint) {
        return codePoint == 0x09 || codePoint == 0x0A || codePoint == 0x0D
            || (codePoint >= 0x20 && codePoint <= 0x7E)
            || codePoint == 0x85
            || (codePoint >= 0xA0 && codePoint <= 0xD7FF)
            || (codePoint >= 0xE000 && codePoint <= 0xFFFD)
            || (codePoint >= 0x10000 && codePoint <= 0x10FFFF);
    }

    private RequestParts requestParts(Map<String, Object> root, String path,
                                      List<Map<String, Object>> parameters) {
        String renderedPath = path;
        List<String> query = new ArrayList<>();
        Map<String, String> headers = new LinkedHashMap<>();
        List<String> cookies = new ArrayList<>();
        for (Map<String, Object> parameter : parameters) {
            String name = string(parameter.get("name"));
            String location = string(parameter.get("in"));
            if (name.isBlank() || location.isBlank()) continue;
            Object rawValue = sampleParameterValue(root, parameter);
            if ("path".equals(location)) {
                renderedPath = renderedPath.replace("{" + name + "}", encodePath(serializedValue(rawValue)));
            } else if ("query".equals(location)) {
                appendQueryParameter(query, name, rawValue, parameter);
            } else if ("header".equals(location)
                && !"host".equalsIgnoreCase(name) && !"content-type".equalsIgnoreCase(name)) {
                headers.put(name, serializedValue(rawValue));
            } else if ("cookie".equals(location)) {
                cookies.add(encodeQuery(name) + "=" + encodeQuery(serializedValue(rawValue)));
            }
        }
        if (!cookies.isEmpty()) headers.put("Cookie", String.join("; ", cookies));
        renderedPath = renderedPath.replaceAll("\\{[^}/]+}", "1");
        if (!query.isEmpty()) renderedPath += (renderedPath.contains("?") ? "&" : "?") + String.join("&", query);
        return new RequestParts(renderedPath, headers);
    }

    private BodyParts requestBody(Map<String, Object> root, Map<String, Object> operation,
                                  List<Map<String, Object>> parameters) {
        Map<String, Object> requestBody = map(resolve(root, operation.get("requestBody")));
        Map<String, Object> content = map(requestBody.get("content"));
        if (!content.isEmpty()) {
            String contentType = preferredContentType(content);
            Map<String, Object> media = map(content.get(contentType));
            Object schema = resolve(root, media.get("schema"));
            Object example = mediaExample(root, media);
            if (example == null || emptyContainerExample(example, schema)) {
                example = schemaExample(root, schema, 0, "value");
            }
            String body = bodyString(example, contentType);
            return new BodyParts(body.isBlank() ? Map.of() : Map.of("Content-Type", contentType), body);
        }

        // Swagger 2 request bodies.
        for (Map<String, Object> parameter : parameters) {
            if (!"body".equals(string(parameter.get("in")))) continue;
            Object example = schemaExample(root, resolve(root, parameter.get("schema")), 0,
                string(parameter.get("name")));
            String contentType = firstString(operation.containsKey("consumes")
                ? operation.get("consumes") : root.get("consumes"), "application/json");
            return new BodyParts(Map.of("Content-Type", contentType), bodyString(example, contentType));
        }
        Map<String, Object> form = new LinkedHashMap<>();
        for (Map<String, Object> parameter : parameters) {
            if ("formData".equals(string(parameter.get("in")))) {
                form.put(string(parameter.get("name")), sampleParameterValue(root, parameter));
            }
        }
        if (!form.isEmpty()) {
            String contentType = firstString(operation.containsKey("consumes")
                ? operation.get("consumes") : root.get("consumes"), "application/x-www-form-urlencoded");
            return new BodyParts(Map.of("Content-Type", contentType), bodyString(form, contentType));
        }
        return new BodyParts(Map.of(), "");
    }

    private Object schemaExample(Map<String, Object> root, Object rawSchema, int depth, String name) {
        if (depth > 5) return null;
        Map<String, Object> schema = map(resolve(root, rawSchema));
        if (schema.isEmpty()) return null;
        if (schema.containsKey("example")) return schema.get("example");
        if (schema.containsKey("default")) return schema.get("default");
        List<Object> enums = list(schema.get("enum"));
        if (!enums.isEmpty()) return enums.get(0);
        for (String composition : List.of("oneOf", "anyOf")) {
            List<Object> alternatives = list(schema.get(composition));
            if (!alternatives.isEmpty()) return schemaExample(root, alternatives.get(0), depth + 1, name);
        }
        List<Object> allOf = list(schema.get("allOf"));
        if (!allOf.isEmpty()) {
            Map<String, Object> merged = new LinkedHashMap<>();
            for (Object part : allOf) {
                Object sample = schemaExample(root, part, depth + 1, name);
                if (sample instanceof Map<?, ?> values) {
                    values.forEach((key, value) -> merged.put(String.valueOf(key), value));
                }
            }
            return merged;
        }
        String type = string(schema.get("type"));
        if (type.isBlank() && schema.containsKey("properties")) type = "object";
        return switch (type) {
            case "object" -> {
                Map<String, Object> value = new LinkedHashMap<>();
                for (Map.Entry<String, Object> property : map(schema.get("properties")).entrySet()) {
                    value.put(property.getKey(), schemaExample(root, property.getValue(), depth + 1,
                        property.getKey()));
                }
                yield value;
            }
            case "array" -> {
                Object item = schemaExample(root, schema.get("items"), depth + 1, name);
                yield item == null ? List.of() : List.of(item);
            }
            case "integer", "number" -> 1;
            case "boolean" -> true;
            default -> formattedString(schema, name);
        };
    }

    private Object mediaExample(Map<String, Object> root, Map<String, Object> media) {
        if (media.containsKey("example")) return resolve(root, media.get("example"));
        Map<String, Object> examples = map(media.get("examples"));
        if (examples.isEmpty()) return null;
        Object first = resolve(root, examples.values().iterator().next());
        Map<String, Object> wrapper = map(first);
        return wrapper.containsKey("value") ? resolve(root, wrapper.get("value")) : first;
    }

    private boolean emptyContainerExample(Object example, Object rawSchema) {
        Map<String, Object> schema = map(rawSchema);
        return (example instanceof Map<?, ?> values && values.isEmpty()
            && !map(schema.get("properties")).isEmpty())
            || (example instanceof List<?> listValues && listValues.isEmpty()
            && !map(schema.get("items")).isEmpty());
    }

    private String formattedString(Map<String, Object> schema, String name) {
        return switch (string(schema.get("format"))) {
            case "date" -> "2026-01-01";
            case "date-time" -> "2026-01-01T00:00:00Z";
            case "uuid" -> "00000000-0000-4000-8000-000000000000";
            case "email" -> "user@example.com";
            default -> name == null || name.isBlank() ? "value" : name;
        };
    }

    private Object sampleParameterValue(Map<String, Object> root, Map<String, Object> parameter) {
        Object value = parameter.get("example");
        if (value == null) value = parameter.get("default");
        if (value == null) value = firstExampleValue(root, parameter.get("examples"));
        if (value == null) value = parameterContentExample(root, parameter);
        Map<String, Object> schema = parameterSchema(root, parameter);
        if (value == null) value = schema.get("example");
        if (value == null) value = schema.get("default");
        List<Object> enumValues = !list(schema.get("enum")).isEmpty()
            ? list(schema.get("enum")) : list(parameter.get("enum"));
        if (value == null && !enumValues.isEmpty()) value = enumValues.get(0);
        String type = !string(schema.get("type")).isBlank()
            ? string(schema.get("type")) : string(parameter.get("type"));
        if (value == null) value = schemaExample(root, schema, 0, string(parameter.get("name")));
        if (value == null) value = "integer".equals(type) || "number".equals(type) ? 1 : "1";
        return value;
    }

    private List<String> servers(Map<String, Object> root, Map<String, Object> pathItem,
                                 Map<String, Object> operation, String baseUrlOverride,
                                 String sourceUrl) {
        if (absoluteHttpUrl(baseUrlOverride)) return List.of(baseUrlOverride);
        Object raw = operation.containsKey("servers") ? operation.get("servers")
            : pathItem.containsKey("servers") ? pathItem.get("servers") : root.get("servers");
        List<String> result = new ArrayList<>();
        for (Object serverObject : list(raw)) {
            Map<String, Object> server = map(serverObject);
            String url = string(server.get("url"));
            for (Map.Entry<String, Object> variable : map(server.get("variables")).entrySet()) {
                Map<String, Object> definition = map(variable.getValue());
                String value = string(definition.get("default"));
                url = url.replace("{" + variable.getKey() + "}", value.isBlank() ? "value" : value);
            }
            if (absoluteHttpUrl(url)) {
                result.add(url);
                break;
            }
            String resolved = resolveServerAgainstSource(url, sourceUrl);
            if (resolved != null) {
                result.add(resolved);
                break;
            }
        }
        if (!result.isEmpty()) return result;

        String host = string(root.get("host"));
        if (!host.isBlank()) {
            String basePath = string(root.get("basePath"));
            List<Object> schemes = list(root.get("schemes"));
            if (schemes.isEmpty()) schemes = List.of("https");
            result.add(schemes.get(0) + "://" + host + basePath);
        }
        if (result.isEmpty()) {
            String implicit = resolveServerAgainstSource("/", sourceUrl);
            if (implicit != null) result.add(implicit);
        }
        return result.isEmpty() ? List.of("https://localhost") : result;
    }

    private Object resolve(Map<String, Object> root, Object value) {
        return resolve(root, value, new HashSet<>());
    }

    private Object resolve(Map<String, Object> root, Object value, Set<String> refs) {
        Map<String, Object> candidate = map(value);
        String ref = string(candidate.get("$ref"));
        if (!ref.startsWith("#/")) return value;
        if (!refs.add(ref)) return null;
        Object current = root;
        for (String token : ref.substring(2).split("/")) {
            current = map(current).get(token.replace("~1", "/").replace("~0", "~"));
            if (current == null) return null;
        }
        return resolve(root, current, refs);
    }

    private List<Map<String, Object>> parameterList(Map<String, Object> root, Object raw) {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list(raw)) {
            Map<String, Object> unresolved = map(item);
            Map<String, Object> parameter = map(resolve(root, item));
            if (unresolved.containsKey("$ref")
                && (parameter.isEmpty() || parameter.containsKey("$ref"))) {
                throw new IllegalArgumentException("Could not resolve OpenAPI parameter reference: "
                    + string(unresolved.get("$ref")));
            }
            result.add(parameter);
        }
        return result;
    }

    private List<Map<String, Object>> combinedParameters(Map<String, Object> root,
                                                         Object pathParameters,
                                                         Object operationParameters) {
        Map<String, Map<String, Object>> combined = new LinkedHashMap<>();
        for (Map<String, Object> parameter : parameterList(root, pathParameters)) {
            combined.put(string(parameter.get("in")) + "\u0000" + string(parameter.get("name")), parameter);
        }
        for (Map<String, Object> parameter : parameterList(root, operationParameters)) {
            combined.put(string(parameter.get("in")) + "\u0000" + string(parameter.get("name")), parameter);
        }
        return List.copyOf(combined.values());
    }

    private String preferredContentType(Map<String, Object> content) {
        for (String preferred : List.of("application/json", "application/x-www-form-urlencoded", "text/plain")) {
            if (content.containsKey(preferred)) return preferred;
        }
        return content.keySet().iterator().next();
    }

    private String bodyString(Object example, String contentType) {
        if (example == null) return "";
        String normalizedType = contentType.toLowerCase(Locale.ROOT);
        if (normalizedType.contains("application/x-www-form-urlencoded") && example instanceof Map<?, ?> values) {
            List<String> fields = new ArrayList<>();
            values.forEach((name, value) -> {
                if (value instanceof List<?> list) {
                    for (Object item : list) {
                        fields.add(encodeQuery(String.valueOf(name)) + "=" + encodeQuery(formScalar(item)));
                    }
                } else {
                    fields.add(encodeQuery(String.valueOf(name)) + "=" + encodeQuery(formScalar(value)));
                }
            });
            return String.join("&", fields);
        }
        if (normalizedType.contains("json") || example instanceof Map || example instanceof List) {
            return gson.toJson(example);
        }
        return String.valueOf(example);
    }

    private String formScalar(Object value) {
        if (value == null) return "";
        return value instanceof Map<?, ?> || value instanceof List<?> ? gson.toJson(value) : String.valueOf(value);
    }

    private String combine(String server, String path) {
        String combined = server.replaceAll("/+$", "") + "/" + path.replaceFirst("^/+", "");
        try {
            URI uri = URI.create(combined);
            return absoluteHttpUrl(combined) && uri.getHost() != null ? uri.toString() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private boolean absoluteHttpUrl(String value) {
        return value != null && (value.startsWith("https://") || value.startsWith("http://"));
    }

    private String encodePath(String value) {
        return encodeQuery(value).replace("+", "%20");
    }

    private String encodeQuery(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private void appendQueryParameter(List<String> query, String name, Object value,
                                      Map<String, Object> parameter) {
        String style = string(parameter.get("style"));
        if (style.isBlank()) style = "form";
        boolean explode = parameter.get("explode") instanceof Boolean declared
            ? declared : "form".equals(style);
        if (value instanceof List<?> values) {
            if (explode) {
                for (Object item : values) query.add(encodeQuery(name) + "=" + encodeQuery(scalar(item)));
            } else {
                query.add(encodeQuery(name) + "=" + encodeQuery(joinScalars(values, ",")));
            }
            return;
        }
        if (value instanceof Map<?, ?> values) {
            if ("deepObject".equals(style)) {
                values.forEach((key, item) -> query.add(encodeQuery(name + "[" + key + "]")
                    + "=" + encodeQuery(scalar(item))));
            } else if (explode) {
                values.forEach((key, item) -> query.add(encodeQuery(String.valueOf(key))
                    + "=" + encodeQuery(scalar(item))));
            } else {
                List<String> flattened = new ArrayList<>();
                values.forEach((key, item) -> {
                    flattened.add(String.valueOf(key));
                    flattened.add(scalar(item));
                });
                query.add(encodeQuery(name) + "=" + encodeQuery(String.join(",", flattened)));
            }
            return;
        }
        query.add(encodeQuery(name) + "=" + encodeQuery(scalar(value)));
    }

    private Map<String, Object> parameterSchema(Map<String, Object> root,
                                                Map<String, Object> parameter) {
        Map<String, Object> schema = map(resolve(root, parameter.get("schema")));
        if (!schema.isEmpty()) return schema;
        Map<String, Object> content = map(parameter.get("content"));
        if (content.isEmpty()) return Map.of();
        Map<String, Object> media = map(content.values().iterator().next());
        return map(resolve(root, media.get("schema")));
    }

    private Object firstExampleValue(Map<String, Object> root, Object rawExamples) {
        Map<String, Object> examples = map(rawExamples);
        if (examples.isEmpty()) return null;
        Object first = resolve(root, examples.values().iterator().next());
        Map<String, Object> wrapper = map(first);
        return wrapper.containsKey("value") ? resolve(root, wrapper.get("value")) : first;
    }

    private Object parameterContentExample(Map<String, Object> root,
                                           Map<String, Object> parameter) {
        Map<String, Object> content = map(parameter.get("content"));
        if (content.isEmpty()) return null;
        Map<String, Object> media = map(content.values().iterator().next());
        if (media.containsKey("example")) return resolve(root, media.get("example"));
        return firstExampleValue(root, media.get("examples"));
    }

    private String serializedValue(Object value) {
        if (value instanceof List<?> values) return joinScalars(values, ",");
        if (value instanceof Map<?, ?> values) {
            List<String> flattened = new ArrayList<>();
            values.forEach((key, item) -> {
                flattened.add(String.valueOf(key));
                flattened.add(scalar(item));
            });
            return String.join(",", flattened);
        }
        return scalar(value);
    }

    private String joinScalars(List<?> values, String delimiter) {
        List<String> strings = new ArrayList<>();
        for (Object value : values) strings.add(scalar(value));
        return String.join(delimiter, strings);
    }

    private String resolveServerAgainstSource(String server, String sourceUrl) {
        if (sourceUrl == null || sourceUrl.isBlank()) return null;
        try {
            URI source = URI.create(sourceUrl.replace("\\", "%5C").replace(" ", "%20"));
            if (!absoluteHttpUrl(source.toString()) || source.getHost() == null) return null;
            URI resolved = source.resolve(server == null || server.isBlank() ? "/" : server);
            return absoluteHttpUrl(resolved.toString()) && resolved.getHost() != null
                ? resolved.toString() : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private boolean isJson(String source, String fileName) {
        String name = fileName == null ? "" : fileName.toLowerCase(Locale.ROOT);
        return name.endsWith(".json") || (source != null && source.stripLeading().startsWith("{"));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> map(Object value) {
        return value instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
    }

    @SuppressWarnings("unchecked")
    private List<Object> list(Object value) {
        return value instanceof List<?> list ? (List<Object>) list : List.of();
    }

    private String string(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    private String scalar(Object value) {
        if (value == null) return "";
        return value instanceof Map<?, ?> || value instanceof List<?> ? gson.toJson(value) : String.valueOf(value);
    }

    private String firstString(Object value, String fallback) {
        List<Object> values = list(value);
        return values.isEmpty() ? fallback : string(values.get(0));
    }

    private Map<String, String> merge(Map<String, String> left, Map<String, String> right) {
        Map<String, String> merged = new LinkedHashMap<>(left);
        merged.putAll(right);
        return merged;
    }

    private record RequestParts(String pathAndQuery, Map<String, String> headers) {}
    private record BodyParts(Map<String, String> headers, String body) {}
}
