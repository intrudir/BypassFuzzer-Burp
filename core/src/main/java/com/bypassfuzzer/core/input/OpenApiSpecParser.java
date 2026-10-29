package com.bypassfuzzer.core.input;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.ToNumberPolicy;
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
import java.util.LinkedHashSet;
import java.util.regex.Matcher;

public final class OpenApiSpecParser {

    private static final Set<String> METHODS = Set.of("get", "head", "post", "put", "patch", "delete", "options", "trace");
    private final Gson gson = new Gson();
    private final Gson variableJson = new GsonBuilder()
        .setObjectToNumberStrategy(ToNumberPolicy.LONG_OR_DOUBLE).create();

    public List<OpenApiOperation> parse(String source, String fileName) {
        return parse(source, fileName, "");
    }

    public List<OpenApiOperation> parse(String source, String fileName, String baseUrlOverride) {
        return parse(source, fileName, baseUrlOverride, "");
    }

    public List<OpenApiOperation> parse(String source, String fileName, String baseUrlOverride,
                                 String sourceUrl) {
        return parse(source, fileName, baseUrlOverride, sourceUrl, OpenApiImportOptions.DEFAULT);
    }

    public List<OpenApiOperation> parse(String source, String fileName, String baseUrlOverride,
                                        String sourceUrl, OpenApiImportOptions options) {
        List<OpenApiOperation> operations = parseTemplates(source, fileName, baseUrlOverride, sourceUrl, options);
        Set<String> missing = new LinkedHashSet<>();
        for (OpenApiOperation operation : operations) missing.addAll(operation.unresolvedVariables());
        if (!missing.isEmpty()) throw new OpenApiImportOptions.MissingVariablesException(missing);
        return operations;
    }

    public List<OpenApiOperation> parseTemplates(String source, String fileName, String baseUrlOverride,
                                                String sourceUrl, OpenApiImportOptions options) {
        if (baseUrlOverride != null && !baseUrlOverride.isBlank() && !absoluteHttpUrl(baseUrlOverride)) {
            throw new IllegalArgumentException("OpenAPI base URL must be an absolute HTTP or HTTPS URL");
        }
        Map<String, Object> root = document(source, fileName);

        Map<String, Object> paths = map(root.get("paths"));
        List<OpenApiOperation> operations = new ArrayList<>();
        for (Map.Entry<String, Object> pathEntry : paths.entrySet()) {
            Map<String, Object> pathItem = map(resolve(root, pathEntry.getValue()));
            for (String method : METHODS) {
                Map<String, Object> operation = map(resolve(root, pathItem.get(method)));
                if (operation.isEmpty()) continue;

                ImportContext context = new ImportContext(options == null ? OpenApiImportOptions.DEFAULT : options);
                List<Map<String, Object>> parameters = combinedParameters(root,
                    pathItem.get("parameters"), operation.get("parameters"));
                RequestParts parts = requestParts(root, pathEntry.getKey(), parameters, context);
                BodyParts bodyParts = requestBody(root, operation, parameters, context);
                for (String server : servers(root, pathItem, operation, baseUrlOverride, sourceUrl, context)) {
                    String url = combine(server, parts.pathAndQuery());
                    if (url != null) {
                        operations.add(new OpenApiOperation(method.toUpperCase(Locale.ROOT), url,
                            merge(parts.headers(), bodyParts.headers()), bodyParts.body(),
                            new OpenApiOperation.Source(serverIdentity(root, pathItem, operation, sourceUrl),
                                pathEntry.getKey()), context.missing));
                    }
                }
            }
        }
        if (operations.isEmpty()) {
            throw new IllegalArgumentException("OpenAPI specification contains no operations with an absolute HTTP(S) server URL");
        }
        return List.copyOf(operations);
    }

    private Map<String, Object> document(String source, String fileName) {
        if (source != null && !source.isEmpty() && source.charAt(0) == '\ufeff') {
            source = source.substring(1);
        }
        source = removeYamlForbiddenCharacters(source);
        Object loaded = isJson(source, fileName)
            ? gson.fromJson(source, Object.class)
            : new Yaml(new SafeConstructor(new LoaderOptions())).load(source);
        Map<String, Object> root = map(loaded);
        if (root.isEmpty() || (!root.containsKey("openapi") && !root.containsKey("swagger"))) {
            throw new IllegalArgumentException("File is not an OpenAPI or Swagger specification");
        }

        return root;
    }

    /** Request variables with spec examples/defaults or generated suggestions. */
    public Map<String, String> variableSamples(String source, String fileName) {
        Map<String, Object> root = document(source, fileName);
        VariableExamples examples = new VariableExamples();
        for (var pathEntry : map(root.get("paths")).entrySet()) {
            Map<String, Object> path = map(resolve(root, pathEntry.getValue()));
            for (String method : METHODS) {
                Map<String, Object> operation = map(resolve(root, path.get(method)));
                if (operation.isEmpty()) continue;
                examples.placeholders(pathEntry.getKey());
                for (Map<String, Object> scope : List.of(root, path, operation)) {
                    for (Object raw : list(scope.get("servers"))) {
                        Map<String, Object> server = map(raw);
                        examples.placeholders(string(server.get("url")));
                        for (var variable : map(server.get("variables")).entrySet()) {
                            Object declared = map(variable.getValue()).get("default");
                            examples.add(variable.getKey(), declared == null ? "value" : declared,
                                declared == null ? 1 : 2);
                        }
                    }
                }
                examples.placeholders(string(root.get("host")));
                examples.placeholders(string(root.get("basePath")));
                List<Map<String, Object>> parameters = combinedParameters(root,
                    path.get("parameters"), operation.get("parameters"));
                for (Map<String, Object> parameter : parameters) {
                    String location = string(parameter.get("in"));
                    String name = string(parameter.get("name"));
                    if (!Set.of("path", "query", "header", "cookie", "formData").contains(location)) continue;
                    if ("header".equals(location)
                        && ("host".equalsIgnoreCase(name) || "content-type".equalsIgnoreCase(name))) continue;
                    Object declared = sourceParameterValue(root, parameter);
                    examples.add(name, declared == null ? sampleParameterValue(root, parameter) : declared,
                        declared == null ? 1 : 2);
                }
                ImportContext context = new ImportContext(OpenApiImportOptions.DEFAULT);
                requestBody(root, operation, parameters, context);
                for (String name : context.missing) examples.add(name, null, 0);
            }
        }
        examples.values.replaceAll((name, value) -> value.isEmpty() && !examples.conflicts.contains(name)
            ? name : value);
        return java.util.Collections.unmodifiableMap(new java.util.TreeMap<>(examples.values));
    }

    private final class VariableExamples {
        private final Map<String, String> values = new LinkedHashMap<>();
        private final Set<String> conflicts = new HashSet<>();
        // Spec values (2) take precedence over generated samples (1).
        private final Map<String, Integer> priorities = new LinkedHashMap<>();

        private void add(String name, Object example, int priority) {
            if (name.isBlank()) return;
            values.putIfAbsent(name, "");
            if (example == null) return;
            String candidate = scalar(example);
            placeholders(candidate);
            Matcher tokens = OpenApiOperation.VARIABLE.matcher(candidate);
            while (tokens.find()) {
                String referenced = tokens.group(1) == null ? tokens.group(2) : tokens.group(1);
                if (name.equals(referenced)) return;
            }
            int previousPriority = priorities.getOrDefault(name, -1);
            if (candidate.isEmpty() || priority < previousPriority) return;
            if (priority > previousPriority) {
                values.put(name, candidate);
                priorities.put(name, priority);
                conflicts.remove(name);
            } else if (!values.get(name).equals(candidate)) {
                values.put(name, "");
                conflicts.add(name);
            }
        }

        private void placeholders(String value) {
            Matcher matcher = OpenApiOperation.VARIABLE.matcher(value);
            while (matcher.find()) {
                String name = matcher.group(1) == null ? matcher.group(2) : matcher.group(1);
                values.putIfAbsent(name, "");
            }
        }
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
                                      List<Map<String, Object>> parameters, ImportContext context) {
        String renderedPath = path;
        List<String> query = new ArrayList<>();
        Map<String, String> headers = new LinkedHashMap<>();
        List<String> cookies = new ArrayList<>();
        for (Map<String, Object> parameter : parameters) {
            String name = string(parameter.get("name"));
            String location = string(parameter.get("in"));
            if (name.isBlank() || location.isBlank()) continue;
            if (!Set.of("path", "query", "header", "cookie").contains(location)) continue;
            if ("header".equals(location)
                && ("host".equalsIgnoreCase(name) || "content-type".equalsIgnoreCase(name))) continue;
            Object rawValue = parameterValue(root, parameter, context);
            if (rawValue == OMIT) continue;
            if ("path".equals(location)) {
                renderedPath = renderedPath.replace("{" + name + "}", encodePath(serializedValue(rawValue)));
            } else if ("query".equals(location)) {
                appendQueryParameter(query, name, rawValue, parameter);
            } else if ("header".equals(location)) {
                String value = serializedValue(rawValue);
                if (value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0) {
                    throw new IllegalArgumentException("OpenAPI header contains a newline: " + name);
                }
                headers.put(name, value);
            } else if ("cookie".equals(location)) {
                cookies.add(encodeQuery(name) + "=" + encodeQuery(serializedValue(rawValue)));
            }
        }
        if (!cookies.isEmpty()) headers.put("Cookie", String.join("; ", cookies));
        Matcher remaining = OpenApiOperation.VARIABLE.matcher(renderedPath);
        StringBuffer completed = new StringBuffer();
        while (remaining.find()) {
            String name = remaining.group(1) == null ? remaining.group(2) : remaining.group(1);
            String value = context.missing.contains(name) ? "{{" + name + "}}"
                : context.options.parameterPolicy() == OpenApiImportOptions.ParameterPolicy.SAMPLE_VALUES
                    && !context.hasValue(name) ? "1" : context.variable(name);
            remaining.appendReplacement(completed, Matcher.quoteReplacement(encodePath(value)));
        }
        remaining.appendTail(completed);
        renderedPath = completed.toString();
        if (!query.isEmpty()) renderedPath += (renderedPath.contains("?") ? "&" : "?") + String.join("&", query);
        return new RequestParts(renderedPath, headers);
    }

    private BodyParts requestBody(Map<String, Object> root, Map<String, Object> operation,
                                  List<Map<String, Object>> parameters, ImportContext context) {
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
            String body = bodyString(context.resolveValue(example), contentType);
            return new BodyParts(body.isBlank() ? Map.of() : Map.of("Content-Type", contentType), body);
        }

        // Swagger 2 request bodies.
        for (Map<String, Object> parameter : parameters) {
            if (!"body".equals(string(parameter.get("in")))) continue;
            Object example = schemaExample(root, resolve(root, parameter.get("schema")), 0,
                string(parameter.get("name")));
            String contentType = firstString(operation.containsKey("consumes")
                ? operation.get("consumes") : root.get("consumes"), "application/json");
            return new BodyParts(Map.of("Content-Type", contentType), bodyString(context.resolveValue(example), contentType));
        }
        Map<String, Object> form = new LinkedHashMap<>();
        for (Map<String, Object> parameter : parameters) {
            if ("formData".equals(string(parameter.get("in")))) {
                Object value = parameterValue(root, parameter, context);
                if (value != OMIT) form.put(string(parameter.get("name")), value);
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
        if (schema.get("example") != null) return schema.get("example");
        if (schema.get("default") != null) return schema.get("default");
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

    private Object sourceParameterValue(Map<String, Object> root, Map<String, Object> parameter) {
        Object value = parameter.get("example");
        if (value == null) value = parameter.get("default");
        if (value == null) value = firstExampleValue(root, parameter.get("examples"));
        if (value == null) value = parameterContentExample(root, parameter);
        Map<String, Object> schema = parameterSchema(root, parameter);
        if (value == null) value = schema.get("example");
        if (value == null) value = schema.get("default");
        return value;
    }

    private static final Object OMIT = new Object();

    private Object parameterValue(Map<String, Object> root, Map<String, Object> parameter,
                                  ImportContext context) {
        String name = string(parameter.get("name"));
        boolean path = "path".equals(string(parameter.get("in")));
        boolean required = path || Boolean.TRUE.equals(parameter.get("required"));
        OpenApiImportOptions.ParameterPolicy policy = context.options.parameterPolicy();
        if (context.hasValue(name) || policy == OpenApiImportOptions.ParameterPolicy.ALL_VARIABLES) {
            String value = context.variable(name);
            Map<String, Object> schema = parameterSchema(root, parameter);
            String type = string(schema.getOrDefault("type", parameter.get("type")));
            if (!OpenApiOperation.VARIABLE.matcher(value).find()
                && (("array".equals(type) && value.startsWith("["))
                    || ("object".equals(type) && value.startsWith("{")))) {
                Object structured = variableJson.fromJson(value, Object.class);
                if (structured instanceof List<?> || structured instanceof Map<?, ?>) return structured;
            }
            return value;
        }
        Object source = sourceParameterValue(root, parameter);
        if (source != null) return context.resolveValue(source);
        if (policy == OpenApiImportOptions.ParameterPolicy.SAMPLE_VALUES) {
            return context.resolveValue(sampleParameterValue(root, parameter));
        }
        if (path || required && policy == OpenApiImportOptions.ParameterPolicy.REQUIRED_VARIABLES) {
            return context.variable(name);
        }
        if (policy == OpenApiImportOptions.ParameterPolicy.ALL_EMPTY
            || required && policy == OpenApiImportOptions.ParameterPolicy.REQUIRED_EMPTY) return "";
        return OMIT;
    }

    private Object sampleParameterValue(Map<String, Object> root, Map<String, Object> parameter) {
        Object value = sourceParameterValue(root, parameter);
        Map<String, Object> schema = parameterSchema(root, parameter);
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
                                 String sourceUrl, ImportContext context) {
        if (absoluteHttpUrl(baseUrlOverride)) return List.of(context.resolveText(baseUrlOverride));
        Object raw = operation.containsKey("servers") ? operation.get("servers")
            : pathItem.containsKey("servers") ? pathItem.get("servers") : root.get("servers");
        List<String> result = new ArrayList<>();
        for (Object serverObject : list(raw)) {
            Map<String, Object> server = map(serverObject);
            String url = string(server.get("url"));
            for (Map.Entry<String, Object> variable : map(server.get("variables")).entrySet()) {
                Map<String, Object> definition = map(variable.getValue());
                String value = string(definition.get("default"));
                String name = variable.getKey();
                String resolved = context.hasValue(name)
                    || context.options.parameterPolicy() == OpenApiImportOptions.ParameterPolicy.ALL_VARIABLES
                    ? context.variable(name) : context.resolveText(value.isBlank() ? "value" : value);
                url = url.replace("{" + name + "}", resolved);
            }
            url = context.resolveText(url);
            if (absoluteHttpUrl(OpenApiOperation.previewUri(url).toString())) {
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

        String host = context.resolveText(string(root.get("host")));
        if (!host.isBlank()) {
            String basePath = context.resolveText(string(root.get("basePath")));
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

    private String serverIdentity(Map<String, Object> root, Map<String, Object> path,
                                  Map<String, Object> operation, String sourceUrl) {
        Object raw = operation.containsKey("servers") ? operation.get("servers")
            : path.containsKey("servers") ? path.get("servers") : root.get("servers");
        List<Object> declared = list(raw);
        if (!declared.isEmpty()) return string(map(declared.get(0)).get("url"));
        return string(root.get("host")) + string(root.get("basePath")) + string(sourceUrl);
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
            URI uri = OpenApiOperation.previewUri(combined);
            return absoluteHttpUrl(uri.toString()) && uri.getHost() != null ? combined : null;
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
        Matcher matcher = OpenApiOperation.VARIABLE.matcher(value);
        StringBuilder encoded = new StringBuilder();
        int offset = 0;
        while (matcher.find()) {
            encoded.append(URLEncoder.encode(value.substring(offset, matcher.start()), StandardCharsets.UTF_8));
            encoded.append(matcher.group());
            offset = matcher.end();
        }
        return encoded.append(URLEncoder.encode(value.substring(offset), StandardCharsets.UTF_8)).toString();
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
            String relative = server == null || server.isBlank() ? "/" : server;
            // Escape only placeholders for URI.resolve, then restore them for the request viewer.
            Matcher matcher = OpenApiOperation.VARIABLE.matcher(relative);
            Map<String, String> tokens = new LinkedHashMap<>();
            StringBuffer escaped = new StringBuffer();
            while (matcher.find()) {
                String token = "%7B%7B" + tokens.size() + "%7D%7D";
                tokens.put(token, matcher.group());
                matcher.appendReplacement(escaped, Matcher.quoteReplacement(token));
            }
            matcher.appendTail(escaped);
            URI resolved = source.resolve(escaped.toString());
            String value = resolved.toString();
            for (var token : tokens.entrySet()) value = value.replace(token.getKey(), token.getValue());
            return absoluteHttpUrl(value) && resolved.getHost() != null ? value : null;
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

    private static final class ImportContext {
        private final OpenApiImportOptions options;
        private final Set<String> missing = new LinkedHashSet<>();
        private final Set<String> resolving = new HashSet<>();

        private ImportContext(OpenApiImportOptions options) { this.options = options; }

        private boolean hasValue(String name) {
            String value = options.variables().get(name);
            return value != null && !value.isEmpty();
        }

        private String variable(String name) {
            if (!hasValue(name) || !resolving.add(name)) {
                missing.add(name);
                return "{{" + name + "}}";
            }
            String value = resolveText(options.variables().get(name));
            resolving.remove(name);
            return value;
        }

        private String resolveText(String value) {
            Matcher matcher = OpenApiOperation.VARIABLE.matcher(value);
            StringBuffer out = new StringBuffer();
            while (matcher.find()) {
                String name = matcher.group(1) == null ? matcher.group(2) : matcher.group(1);
                matcher.appendReplacement(out, Matcher.quoteReplacement(variable(name)));
            }
            matcher.appendTail(out);
            return out.toString();
        }

        private Object resolveValue(Object value) {
            if (value instanceof String text) return resolveText(text);
            if (value instanceof List<?> values) return values.stream().map(this::resolveValue).toList();
            if (value instanceof Map<?, ?> values) {
                Map<String, Object> resolved = new LinkedHashMap<>();
                values.forEach((key, item) -> resolved.put(String.valueOf(key), resolveValue(item)));
                return resolved;
            }
            return value;
        }


    }

    private record RequestParts(String pathAndQuery, Map<String, String> headers) {}
    private record BodyParts(Map<String, String> headers, String body) {}
}
