package com.bypassfuzzer.cli.input;

import com.bypassfuzzer.core.http.HttpHeader;
import com.bypassfuzzer.core.input.RetryPackage;
import com.bypassfuzzer.core.input.RetryPackageEntry;
import com.bypassfuzzer.core.http.HttpProtocol;
import com.bypassfuzzer.core.http.HttpRequestData;
import com.bypassfuzzer.core.http.RawHttpRequestParser;
import com.bypassfuzzer.core.http.TargetOrigin;
import com.bypassfuzzer.core.input.OpenApiOperation;
import com.bypassfuzzer.core.input.OpenApiSpecParser;
import com.bypassfuzzer.core.input.PostmanCollectionParser;
import com.google.gson.Gson;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class CliRequestLoader {
    private final RawHttpRequestParser rawParser = new RawHttpRequestParser();

    public List<HttpRequestData> raw(Path requestFile, String targetOrigin) throws IOException {
        if (requestFile == null || targetOrigin == null) {
            throw new IllegalArgumentException("--request and --target-origin must be supplied together");
        }
        return List.of(rawParser.parse(Files.readAllBytes(requestFile), TargetOrigin.parse(targetOrigin)));
    }

    public List<HttpRequestData> urls(Path file, boolean includeStateChanging) throws IOException {
        List<HttpRequestData> requests = new ArrayList<>();
        for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            String value = line.trim();
            if (value.isEmpty() || value.startsWith("#")) continue;
            requests.add(fromUrl("GET", value, Map.of(), ""));
        }
        if (requests.isEmpty()) throw new IllegalArgumentException("URL list contains no usable HTTP(S) URLs");
        return List.copyOf(requests);
    }

    @SuppressWarnings("unchecked")
    public List<HttpRequestData> manifest(Path file) throws IOException {
        Object loaded = yaml().load(Files.readString(file, StandardCharsets.UTF_8));
        Object rows = loaded instanceof Map<?, ?> map ? map.get("requests") : loaded;
        if (!(rows instanceof List<?> entries)) throw new IllegalArgumentException("Request manifest must be a list or contain a requests list");
        List<HttpRequestData> requests = new ArrayList<>();
        for (Object entry : entries) {
            if (!(entry instanceof Map<?, ?> map)) throw new IllegalArgumentException("Every request manifest entry must be an object");
            Object requestFile = map.get("requestFile");
            Object targetOrigin = map.get("targetOrigin");
            if (requestFile == null || targetOrigin == null) throw new IllegalArgumentException("Manifest entries require requestFile and targetOrigin");
            Path resolved = file.toAbsolutePath().getParent().resolve(requestFile.toString()).normalize();
            requests.add(rawParser.parse(Files.readAllBytes(resolved), TargetOrigin.parse(targetOrigin.toString())));
        }
        if (requests.isEmpty()) throw new IllegalArgumentException("Request manifest is empty");
        return List.copyOf(requests);
    }

    public List<HttpRequestData> openApi(String location, String baseUrl, boolean includeStateChanging,
                                        com.bypassfuzzer.core.input.OpenApiImportOptions options,
                                        boolean fillExamples) throws Exception {
        Source source = readLocation(location);
        OpenApiSpecParser parser = new OpenApiSpecParser();
        if (fillExamples) {
            Map<String, String> variables = new java.util.LinkedHashMap<>(options.variables());
            parser.variableSamples(source.text(), source.name()).forEach((name, value) -> {
                if (variables.getOrDefault(name, "").isEmpty() && !value.isEmpty()) variables.put(name, value);
            });
            options = new com.bypassfuzzer.core.input.OpenApiImportOptions(options.parameterPolicy(), variables);
        }
        List<OpenApiOperation> operations = parser.parseTemplates(source.text(), source.name(), baseUrl, source.url(), options);
        return operations(operations, includeStateChanging);
    }

    public List<HttpRequestData> postman(Path file, String baseUrl, boolean includeStateChanging) throws IOException {
        String source = Files.readString(file, StandardCharsets.UTF_8);
        return operations(new PostmanCollectionParser().parse(source, baseUrl), includeStateChanging);
    }

    public List<RetryPackageEntry> retryEntries(Path file) throws IOException {
        RetryPackage retry;
        try { retry = new Gson().fromJson(Files.readString(file, StandardCharsets.UTF_8), RetryPackage.class); }
        catch (RuntimeException error) { throw new IllegalArgumentException("Invalid retry-package JSON", error); }
        if (retry == null || retry.entries().isEmpty()) throw new IllegalArgumentException("Retry package contains no requests");
        for (var entry : retry.entries()) entry.planned();
        return retry.entries();
    }

    public List<HttpRequestData> retryPackage(Path file) throws IOException {
        return retryEntries(file).stream().map(entry -> entry.planned().request()).toList();
    }

    private List<HttpRequestData> operations(List<OpenApiOperation> operations, boolean includeStateChanging) {
        List<OpenApiOperation> selected = operations.stream()
            .filter(operation -> includeStateChanging || safeMethod(operation.method()))
            .toList();
        var missing = new java.util.LinkedHashSet<String>();
        for (var operation : selected) missing.addAll(operation.unresolvedVariables());
        if (!missing.isEmpty()) throw new com.bypassfuzzer.core.input.OpenApiImportOptions.MissingVariablesException(missing);
        List<HttpRequestData> requests = selected.stream()
            .map(operation -> fromUrl(operation.method(), operation.url(), operation.headers(), operation.body()))
            .toList();
        if (requests.isEmpty()) throw new IllegalArgumentException("Input contains no enabled HTTP operations");
        return requests;
    }

    private HttpRequestData fromUrl(String method, String value, Map<String, String> headers, String body) {
        URI uri;
        try { uri = URI.create(value); } catch (RuntimeException exception) { throw new IllegalArgumentException("Invalid HTTP URL: " + value, exception); }
        TargetOrigin origin = origin(uri);
        String rawTarget = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        if (uri.getRawQuery() != null) rawTarget += "?" + uri.getRawQuery();
        List<HttpHeader> requestHeaders = new ArrayList<>();
        requestHeaders.add(new HttpHeader("Host", origin.authority()));
        headers.forEach((name, headerValue) -> requestHeaders.add(new HttpHeader(name, headerValue)));
        byte[] bytes = body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > 0 && requestHeaders.stream().noneMatch(header -> header.name().equalsIgnoreCase("Content-Length"))) {
            requestHeaders.add(new HttpHeader("Content-Length", String.valueOf(bytes.length)));
        }
        return new HttpRequestData(origin, method.toUpperCase(), rawTarget, HttpProtocol.AUTO, requestHeaders, bytes);
    }

    private TargetOrigin origin(URI uri) {
        if (uri.getScheme() == null || uri.getHost() == null || !(uri.getScheme().equalsIgnoreCase("http") || uri.getScheme().equalsIgnoreCase("https"))) {
            throw new IllegalArgumentException("Input destination must be an absolute HTTP(S) URL: " + uri);
        }
        return TargetOrigin.parse(uri.getScheme() + "://" + uri.getRawAuthority());
    }

    private Source readLocation(String location) throws Exception {
        URI uri;
        try { uri = URI.create(location); } catch (RuntimeException ignored) { uri = null; }
        if (uri != null && ("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()))) {
            HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(10)).build();
            HttpResponse<String> response = client.send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(30)).GET().build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() < 200 || response.statusCode() >= 300) throw new IllegalArgumentException("OpenAPI fetch returned HTTP " + response.statusCode());
            String path = uri.getPath();
            String name = path == null || path.isBlank() || Path.of(path).getFileName() == null
                ? "openapi"
                : Path.of(path).getFileName().toString();
            return new Source(response.body(), name, uri.toString());
        }
        Path file = Path.of(location);
        return new Source(Files.readString(file, StandardCharsets.UTF_8), file.getFileName().toString(), "");
    }

    private boolean safeMethod(String method) { return method.equalsIgnoreCase("GET") || method.equalsIgnoreCase("HEAD") || method.equalsIgnoreCase("OPTIONS"); }
    private Yaml yaml() { LoaderOptions options = new LoaderOptions(); options.setAllowDuplicateKeys(false); options.setMaxAliasesForCollections(50); return new Yaml(new SafeConstructor(options)); }

    private record Source(String text, String name, String url) {}
}
