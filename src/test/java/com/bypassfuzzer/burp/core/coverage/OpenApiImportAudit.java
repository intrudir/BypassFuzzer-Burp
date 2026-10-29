package com.bypassfuzzer.burp.core.coverage;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.http.RequestSender;
import com.bypassfuzzer.burp.smoke.MontoyaStubs;
import com.bypassfuzzer.core.input.OpenApiImportOptions;
import com.bypassfuzzer.core.input.OpenApiSpecParser;
import com.google.gson.*;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.*;

import static org.mockito.Mockito.*;

/** Offline contract audit: real import and probe generation, with no network transport. */
public final class OpenApiImportAudit {
    private static final Set<String> METHODS = Set.of("get", "post", "put", "patch", "delete", "head", "options", "trace");
    private static final Gson JSON = new GsonBuilder().setPrettyPrinting().create();

    public static void main(String[] args) throws Exception {
        if (args.length < 2) throw new IllegalArgumentException("Usage: <spec.json> <output-directory> [source-url]");
        Path spec = Path.of(args[0]);
        Path output = Path.of(args[1]);
        String sourceUrl = args.length > 2 ? args[2] : "https://example.test/docs/openapi.json";
        Map<String, Object> report = audit(Files.readString(spec), sourceUrl, output);
        Files.copy(spec, output.resolve("source.json"), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        Files.writeString(output.resolve("report.json"), JSON.toJson(report));
        System.out.println("PASS: " + report.get("operations") + " operations, " + report.get("scenarios")
            + " scenarios, " + report.get("checkedRequests") + " imported/control request pairs.");
        System.out.println("Report: " + output.resolve("report.json").toAbsolutePath());
    }

    static Map<String, Object> audit(String source, String sourceUrl, Path output) throws Exception {
        Files.createDirectories(output);
        JsonObject root = JsonParser.parseString(source).getAsJsonObject();
        JsonObject paths = root.getAsJsonObject("paths");
        int operationCount = paths.entrySet().stream().mapToInt(entry -> (int) entry.getValue().getAsJsonObject()
            .keySet().stream().filter(METHODS::contains).count()).sum();
        var parser = new OpenApiSpecParser();
        Map<String, String> samples = parser.variableSamples(source, "openapi.json");
        RequestSender sender = mock(RequestSender.class);
        CoverageSweepEngine engine = new CoverageSweepEngine(mock(MontoyaApi.class), sender,
            new CoverageSweepProbeGenerator(), OpenApiImportAudit::request);
        CoverageSweepOptions options = new CoverageSweepOptions(Set.of(403), false, 1000, 2, 1, 1, Set.of(429, 503));
        List<Map<String, Object>> rows = new ArrayList<>();
        List<String> overrides = List.of("", "https://" + URI.create(sourceUrl).getRawAuthority());
        int scenarios = 0;
        for (String baseUrl : overrides) {
            for (OpenApiImportOptions.ParameterPolicy policy : OpenApiImportOptions.ParameterPolicy.values()) {
                for (boolean filled : List.of(false, true)) {
                    scenarios++;
                    Map<String, String> variables = filled ? samples : Map.of();
                    String scenario = (baseUrl.isEmpty() ? "declared" : "https-override") + "-" + policy.name()
                        + (filled ? "-filled" : "-empty");
                    Path directory = output.resolve(scenario);
                    Files.createDirectories(directory);
                    var preview = engine.collectPreviewFromOpenApi(source, "openapi.json", baseUrl, sourceUrl,
                        options, false, new OpenApiImportOptions(policy, variables));
                    require(preview.blockedHistoryCount() == operationCount, scenario + ": parser lost an operation");
                    require(preview.candidates().size() == operationCount, scenario + ": request conversion lost an operation");
                    Set<String> imported = new HashSet<>();
                    int index = 0;
                    for (CoverageSweepCandidate candidate : preview.candidates()) {
                        String sourcePath = candidate.importKey().substring(candidate.importKey().lastIndexOf('\0') + 1);
                        JsonObject path = paths.getAsJsonObject(sourcePath);
                        JsonObject operation = path.getAsJsonObject(candidate.method().toLowerCase(Locale.ROOT));
                        String label = scenario + " " + candidate.method() + " " + sourcePath;
                        require(operation != null, label + ": undocumented method/path");
                        require(imported.add(candidate.method() + " " + sourcePath), label + ": duplicate operation");
                        List<JsonObject> parameters = parameters(root, path, operation);
                        String expectedPath = sourcePath;
                        Map<String, List<String>> expectedQuery = new TreeMap<>();
                        Map<String, String> expectedHeaders = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
                        for (JsonObject parameter : parameters) {
                            String name = parameter.get("name").getAsString();
                            String location = parameter.get("in").getAsString();
                            String value = value(root, parameter, variables, samples, policy);
                            if (value != null && !value.isEmpty() && !value.contains("{{")
                                && (filled || policy == OpenApiImportOptions.ParameterPolicy.SAMPLE_VALUES)) {
                                validate(root, parameter.has("schema") ? parameter.get("schema") : new JsonObject(),
                                    typedValue(root, parameter, value), label + " parameter " + name);
                            }
                            if (location.equals("path")) {
                                expectedPath = expectedPath.replace("{" + name + "}", pathEncode(value));
                            } else if (value != null && location.equals("query")) {
                                JsonElement typed = typedValue(root, parameter, value);
                                if (typed.isJsonArray()) {
                                    require(!parameter.has("style") || parameter.get("style").getAsString().equals("form"),
                                        label + ": audit needs explicit expectations for this query-array style");
                                    List<String> entries = new ArrayList<>();
                                    for (JsonElement entry : typed.getAsJsonArray()) entries.add(scalar(entry));
                                    boolean explode = !parameter.has("explode") || parameter.get("explode").getAsBoolean();
                                    expectedQuery.put(name, explode ? entries : List.of(String.join(",", entries)));
                                } else {
                                    require(!typed.isJsonObject(), label + ": audit needs explicit expectations for object query " + name);
                                    expectedQuery.put(name, List.of(scalar(typed)));
                                }
                            } else if (value != null && location.equals("header")) {
                                expectedHeaders.put(name, value);
                            } else if (location.equals("cookie") || location.equals("formData")) {
                                throw new IllegalArgumentException("Audit needs explicit expectations for " + location + " parameters");
                            }
                        }
                        JsonObject serverScope = operation.has("servers") ? operation : path.has("servers") ? path : root;
                        String server = !baseUrl.isEmpty() ? baseUrl : serverScope.has("servers")
                            ? serverScope.getAsJsonArray("servers").get(0).getAsJsonObject().get("url").getAsString()
                            : URI.create(sourceUrl).resolve("/").toString();
                        URI origin = URI.create(server);
                        require(origin.getHost() != null, label + ": audit expects a concrete HTTP server");
                        String prefix = origin.getRawPath() == null ? "" : origin.getRawPath().replaceAll("/+$", "");
                        expectedPath = prefix + "/" + expectedPath.replaceFirst("^/+", "");
                        String actualPath = candidate.request().path().split("\\?", 2)[0];
                        require(actualPath.equals(expectedPath), label + ": wrong path: " + actualPath + " vs " + expectedPath);
                        require(query(candidate.request().path()).equals(expectedQuery), label + ": query mismatch: "
                            + query(candidate.request().path()) + " vs " + expectedQuery);
                        boolean secure = origin.getScheme().equalsIgnoreCase("https");
                        int port = origin.getPort() >= 0 ? origin.getPort() : secure ? 443 : 80;
                        var service = candidate.request().httpService();
                        require(service.host().equals(origin.getHost()) && service.port() == port && service.secure() == secure,
                            label + ": wrong connection target");
                        String host = origin.getHost() + (port == (secure ? 443 : 80) ? "" : ":" + port);
                        require(host.equals(candidate.request().headerValue("Host")), label + ": wrong Host header");
                        expectedHeaders.put("Host", host);
                        require(headers(candidate.request()).equals(expectedHeaders), label + ": headers added or dropped");
                        require(!operation.has("requestBody"), label + ": audit needs a body expectation for this operation");
                        require(candidate.request().bodyToString().isEmpty(), label + ": invented request body");
                        var controls = engine.buildProbes(candidate, options).stream()
                            .filter(probe -> probe.family().equals("Control")).toList();
                        require(controls.size() == 1, label + ": missing or duplicate control");
                        HttpRequest control = controls.get(0).request();
                        require(control.toString().equals(candidate.request().toString()), label + ": control differs from import");
                        require(control.httpService().host().equals(service.host()) && control.httpService().port() == service.port()
                            && control.httpService().secure() == service.secure(), label + ": control origin differs");
                        if (!candidate.unresolvedVariables().isEmpty()) {
                            require(!engine.start(List.of(candidate), options, result -> {}, () -> {}), label + ": unresolved request can send");
                        }
                        String file = String.format(Locale.ROOT, "%02d-%s.http", ++index, candidate.method());
                        Files.writeString(directory.resolve(file), candidate.request().toString());
                        rows.add(Map.of("scenario", scenario, "method", candidate.method(), "path", sourcePath,
                            "queryFields", expectedQuery.size(), "bodyBytes", 0, "request", scenario + "/" + file,
                            "unresolved", new TreeSet<>(candidate.unresolvedVariables()), "result", "PASS"));
                    }
                }
            }
        }
        verifyNoInteractions(sender);
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("sourceUrl", sourceUrl);
        report.put("specSha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(source.getBytes(StandardCharsets.UTF_8))));
        report.put("operations", operationCount);
        report.put("scenarios", scenarios);
        report.put("checkedRequests", rows.size());
        report.put("networkRequestsSent", 0);
        report.put("checks", List.of("operation coverage", "parameter policy", "path values", "query names and values",
            "array serialization", "schema types/formats/enums", "scheme/host/port", "headers", "body presence", "control parity", "unresolved execution guard"));
        report.put("requests", rows);
        return report;
    }

    private static List<JsonObject> parameters(JsonObject root, JsonObject path, JsonObject operation) {
        Map<String, JsonObject> combined = new LinkedHashMap<>();
        for (JsonObject scope : List.of(path, operation)) {
            if (!scope.has("parameters")) continue;
            for (JsonElement value : scope.getAsJsonArray("parameters")) {
                JsonObject p = resolve(root, value).getAsJsonObject();
                combined.put(p.get("in").getAsString() + "\0" + p.get("name").getAsString(), p);
            }
        }
        return new ArrayList<>(combined.values());
    }

    private static String value(JsonObject root, JsonObject parameter, Map<String, String> variables,
                                Map<String, String> samples, OpenApiImportOptions.ParameterPolicy policy) {
        String name = parameter.get("name").getAsString();
        if (variables.containsKey(name) && !variables.get(name).isEmpty()) return variables.get(name);
        if (policy == OpenApiImportOptions.ParameterPolicy.ALL_VARIABLES) return "{{" + name + "}}";
        JsonObject schema = parameter.has("schema") ? resolve(root, parameter.get("schema")).getAsJsonObject() : new JsonObject();
        for (JsonElement declared : List.of(parameter.has("example") ? parameter.get("example") : JsonNull.INSTANCE,
            schema.has("default") ? schema.get("default") : JsonNull.INSTANCE,
            schema.has("example") ? schema.get("example") : JsonNull.INSTANCE)) {
            if (!declared.isJsonNull()) return scalar(declared);
        }
        if (policy == OpenApiImportOptions.ParameterPolicy.SAMPLE_VALUES) return samples.get(name);
        boolean path = parameter.get("in").getAsString().equals("path");
        boolean required = path || parameter.has("required") && parameter.get("required").getAsBoolean();
        if (path || required && policy == OpenApiImportOptions.ParameterPolicy.REQUIRED_VARIABLES) return "{{" + name + "}}";
        if (policy == OpenApiImportOptions.ParameterPolicy.ALL_EMPTY
            || required && policy == OpenApiImportOptions.ParameterPolicy.REQUIRED_EMPTY) return "";
        return null;
    }

    private static JsonElement typedValue(JsonObject root, JsonObject parameter, String value) {
        JsonObject schema = parameter.has("schema") ? resolve(root, parameter.get("schema")).getAsJsonObject() : new JsonObject();
        if (schema.has("type") && schema.get("type").getAsString().equals("array") && value.startsWith("[")) {
            return JsonParser.parseString(value);
        }
        return new JsonPrimitive(value);
    }

    private static void validate(JsonObject root, JsonElement rawSchema, JsonElement value, String label) {
        JsonObject schema = resolve(root, rawSchema).getAsJsonObject();
        if (value.isJsonNull()) {
            require(schema.has("nullable") && schema.get("nullable").getAsBoolean(), label + ": unexpected null");
            return;
        }
        if (schema.has("enum")) {
            boolean matches = false;
            for (JsonElement choice : schema.getAsJsonArray("enum")) matches |= scalar(choice).equals(scalar(value));
            require(matches, label + ": value outside enum");
        }
        String type = schema.has("type") ? schema.get("type").getAsString() : "";
        switch (type) {
            case "integer" -> require(new java.math.BigDecimal(value.getAsString()).stripTrailingZeros().scale() <= 0,
                label + ": non-integer value");
            case "number" -> new java.math.BigDecimal(value.getAsString());
            case "boolean" -> require(Set.of("true", "false").contains(value.getAsString()), label + ": invalid boolean");
            case "array" -> {
                require(value.isJsonArray(), label + ": expected array");
                if (schema.has("items")) for (JsonElement item : value.getAsJsonArray()) validate(root, schema.get("items"), item, label + "[]");
            }
            case "object" -> {
                require(value.isJsonObject(), label + ": expected object");
                JsonObject object = value.getAsJsonObject();
                if (schema.has("required")) for (JsonElement name : schema.getAsJsonArray("required"))
                    require(object.has(name.getAsString()), label + ": missing object property " + name.getAsString());
                if (schema.has("properties")) for (var entry : object.entrySet()) {
                    JsonObject properties = schema.getAsJsonObject("properties");
                    if (properties.has(entry.getKey())) validate(root, properties.get(entry.getKey()), entry.getValue(), label + "." + entry.getKey());
                }
            }
            case "string" -> {
                require(value.isJsonPrimitive(), label + ": expected string");
                if (schema.has("format")) switch (schema.get("format").getAsString()) {
                    case "uuid" -> UUID.fromString(value.getAsString());
                    case "date" -> java.time.LocalDate.parse(value.getAsString());
                    case "date-time" -> java.time.OffsetDateTime.parse(value.getAsString());
                    default -> { }
                }
            }
            default -> { }
        }
    }

    private static JsonElement resolve(JsonObject root, JsonElement value) {
        Set<String> visited = new HashSet<>();
        while (value.isJsonObject() && value.getAsJsonObject().has("$ref")) {
            String ref = value.getAsJsonObject().get("$ref").getAsString();
            require(ref.startsWith("#/") && visited.add(ref), "Unsupported or cyclic reference " + ref);
            value = root;
            for (String token : ref.substring(2).split("/")) value = value.getAsJsonObject().get(token.replace("~1", "/").replace("~0", "~"));
        }
        return value;
    }

    private static Map<String, List<String>> query(String target) {
        Map<String, List<String>> values = new TreeMap<>();
        int separator = target.indexOf('?');
        if (separator < 0) return values;
        for (String field : target.substring(separator + 1).split("&")) {
            String[] pair = field.split("=", 2);
            String name = URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
            String value = pair.length > 1 ? URLDecoder.decode(pair[1], StandardCharsets.UTF_8) : "";
            values.computeIfAbsent(name, ignored -> new ArrayList<>()).add(value);
        }
        return values;
    }

    private static Map<String, String> headers(HttpRequest request) {
        Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        request.headers().forEach(header -> headers.put(header.name(), header.value()));
        return headers;
    }

    private static String scalar(JsonElement value) { return value.isJsonPrimitive() ? value.getAsString() : value.toString(); }
    private static String pathEncode(String value) {
        return value.startsWith("{{") ? value : java.net.URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
    private static void require(boolean condition, String message) { if (!condition) throw new AssertionError(message); }

    private static HttpRequest request(URI uri) {
        boolean secure = uri.getScheme().equalsIgnoreCase("https");
        int port = uri.getPort() >= 0 ? uri.getPort() : secure ? 443 : 80;
        String host = uri.getHost() + (port == (secure ? 443 : 80) ? "" : ":" + port);
        String target = uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        if (uri.getRawQuery() != null) target += "?" + uri.getRawQuery();
        return offline(MontoyaStubs.request(MontoyaStubs.httpService(uri.getHost(), port, secure),
            "GET " + target + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"));
    }

    /** Select CoreRequestAdapter's object rebuilding path; native Montoya factories require Burp. */
    private static HttpRequest offline(HttpRequest request) {
        return (HttpRequest) Proxy.newProxyInstance(HttpRequest.class.getClassLoader(), new Class<?>[]{HttpRequest.class},
            (proxy, method, args) -> {
                if (method.getName().equals("toByteArray")) return null;
                try {
                    Object value = method.invoke(request, args);
                    return value instanceof HttpRequest changed ? offline(changed) : value;
                } catch (InvocationTargetException e) { throw e.getCause(); }
            });
    }
}
