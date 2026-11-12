package com.bypassfuzzer.cli;

import com.bypassfuzzer.core.input.OpenApiImportOptions;
import com.bypassfuzzer.core.input.OpenApiSpecParser;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.*;

class CliOpenApiParityTest {
    @TempDir Path temporary;
    private static final String SPEC = """
        {"openapi":"3.0.0","servers":[{"url":"https://example.test"}],"paths":{
          "/objects/{id}":{"get":{"parameters":[
            {"name":"id","in":"path","required":true,"schema":{"type":"integer"}},
            {"name":"tenant","in":"query","required":true,"schema":{"type":"string"}},
            {"name":"optional","in":"query","schema":{"type":"string"}},
            {"name":"q","in":"query","schema":{"type":"string"},"example":"source"},
            {"name":"X-Object","in":"header","required":true,"schema":{"type":"string"}}
          ],"responses":{"200":{"description":"ok"}}}}}}
        """;

    @Test
    void allPoliciesUseTheSameSharedImportAsBurp() throws Exception {
        Path spec = specification();
        for (var policy : OpenApiImportOptions.ParameterPolicy.values()) {
            Map<String, String> variables = new LinkedHashMap<>(Map.of("id", "42", "tenant", "a b", "X-Object", "header-value"));
            if (policy == OpenApiImportOptions.ParameterPolicy.ALL_VARIABLES) {
                variables.put("optional", "value");
                variables.put("q", "source");
            }
            var expected = new OpenApiSpecParser().parse(SPEC, "spec.json", "", "",
                new OpenApiImportOptions(policy, variables)).get(0);
            List<String> args = new ArrayList<>(List.of("sweep", "--preview", "--openapi", spec.toString(),
                "--max-probes", "1", "--families", "Header", "--openapi-parameter-policy", policy.name().toLowerCase().replace('_', '-')));
            variables.forEach((key, value) -> args.addAll(List.of("--openapi-variable", key + "=" + value)));
            Run actual = run(args.toArray(String[]::new));
            assertEquals(0, actual.code(), policy + ": " + actual.error());
            assertTrue(actual.output().contains("GET " + expected.requestTarget() + " HTTP/1.1"), policy.toString());
            expected.headers().forEach((key, value) -> assertTrue(actual.output().contains(key + ": " + value)));
        }
    }

    @Test
    void requiredVariablesAreTheDefaultAndRejectMissingValuesBeforeSending() throws Exception {
        Path output = temporary.resolve("missing-output");
        Run actual = run("sweep", "--no-wildcard-calibration", "--openapi", specification().toString(), "--output", output.toString());
        assertEquals(2, actual.code());
        assertTrue(actual.error().contains("Set OpenAPI variables before running"));
        assertTrue(actual.error().contains("id"));
        assertFalse(Files.exists(output));
    }

    @Test
    void flagsOverrideYamlPerVariableAndCanDisableExampleFilling() throws Exception {
        specification();
        Path job = temporary.resolve("job.yaml");
        Files.writeString(job, """
            schemaVersion: 1
            input:
              openapi: spec.json
              openapiParameterPolicy: all-variables
              openapiFillExamples: true
              openapiVariables:
                id: 10
                tenant: yaml-tenant
                X-Object: yaml-header
            """);
        Run actual = run("sweep", "--config", job.toString(), "--preview", "--families", "Header", "--max-probes", "1",
            "--openapi-parameter-policy", "required-variables", "--no-openapi-fill-examples",
            "--openapi-variable", "id=42", "--openapi-variable", "q=flag=with=equals");
        assertEquals(0, actual.code(), actual.error());
        assertTrue(actual.output().contains("/objects/42?"));
        assertTrue(actual.output().contains("tenant=yaml-tenant"));
        assertTrue(actual.output().contains("q=flag%3Dwith%3Dequals"));
        assertTrue(actual.output().contains("X-Object: yaml-header"));
        assertFalse(actual.output().contains("optional="));
    }

    @Test
    void fillsEmptyValuesFromSharedSamplesWithoutReplacingExplicitValues() throws Exception {
        Path spec = specification();
        Map<String, String> variables = new LinkedHashMap<>(new OpenApiSpecParser().variableSamples(SPEC, "spec.json"));
        variables.put("id", "42");
        variables.put("tenant", "provided");
        var expected = new OpenApiSpecParser().parse(SPEC, "spec.json", "", "",
            new OpenApiImportOptions(OpenApiImportOptions.ParameterPolicy.REQUIRED_VARIABLES, variables)).get(0);
        Run actual = run("sweep", "--preview", "--openapi", spec.toString(), "--families", "Header", "--max-probes", "1",
            "--openapi-fill-examples", "--openapi-variable", "id=42", "--openapi-variable", "tenant=provided");
        assertEquals(0, actual.code(), actual.error());
        assertTrue(actual.output().contains("GET " + expected.requestTarget() + " HTTP/1.1"));
        expected.headers().forEach((key, value) -> assertTrue(actual.output().contains(key + ": " + value)));
    }

    @Test
    void invalidParameterControlsFailAtPreflight() throws Exception {
        Path spec = specification();
        for (List<String> invalid : List.of(List.of("--openapi-parameter-policy", "unknown"),
                List.of("--openapi-variable", "missing-equals"), List.of("--openapi-variable", " =value"))) {
            List<String> args = new ArrayList<>(List.of("sweep", "--preview", "--openapi", spec.toString()));
            args.addAll(invalid);
            assertEquals(2, run(args.toArray(String[]::new)).code());
        }
        Path job = temporary.resolve("nested.yaml");
        Files.writeString(job, "schemaVersion: 1\ninput:\n  openapi: spec.json\n  openapiVariables:\n    id: {nested: value}\n");
        assertEquals(2, run("sweep", "--preview", "--config", job.toString()).code());
        Path urls = temporary.resolve("urls.txt");
        Files.writeString(urls, "https://example.test/\n");
        Run irrelevant = run("sweep", "--preview", "--urls", urls.toString(), "--openapi-variable", "id=42");
        assertEquals(2, irrelevant.code());
        assertTrue(irrelevant.error().contains("OpenAPI parameter controls require"));
    }

    @Test
    void managedVariablesReachTheLoopbackWire() throws Exception {
        List<String> requests = new CopyOnWriteArrayList<>();
        List<String> objectHeaders = new CopyOnWriteArrayList<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            requests.add(exchange.getRequestURI().toASCIIString());
            objectHeaders.add(exchange.getRequestHeaders().getFirst("X-Object"));
            byte[] body = "blocked-loopback-control".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(403, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        try {
            Run actual = run("sweep", "--no-wildcard-calibration", "--openapi", specification().toString(),
                "--base-url", "http://127.0.0.1:" + server.getAddress().getPort(),
                "--openapi-variable", "id=42", "--openapi-variable", "tenant=org", "--openapi-variable", "X-Object=header-value",
                "--families", "Header", "--max-probes", "2", "--retry-attempts", "0", "--protocol", "http1",
                "--output", temporary.resolve("live").toString());
            assertEquals(0, actual.code(), actual.error());
            assertEquals(2, requests.size());
            assertTrue(requests.stream().allMatch(path -> path.startsWith("/objects/42?") && path.contains("tenant=org")));
            assertEquals(List.of("header-value", "header-value"), objectHeaders);
        } finally { server.stop(0); }
    }

    @Test
    void excludedStateChangingOperationsDoNotRequireTheirVariables() throws Exception {
        Path spec = temporary.resolve("mixed.json");
        Files.writeString(spec, """
            {"openapi":"3.0.0","servers":[{"url":"https://example.test"}],"paths":{
              "/public":{"get":{"responses":{"200":{"description":"ok"}}}},
              "/objects/{id}":{"post":{"parameters":[
                {"name":"id","in":"path","required":true,"schema":{"type":"integer"}}
              ],"responses":{"200":{"description":"ok"}}}}}}
            """);
        Run safe = run("sweep", "--preview", "--openapi", spec.toString(), "--max-probes", "1");
        assertEquals(0, safe.code(), safe.error());
        assertTrue(safe.output().contains("GET /public HTTP/1.1"));
        assertFalse(safe.output().contains("POST "));
        Run unsafe = run("sweep", "--preview", "--openapi", spec.toString(), "--include-state-changing");
        assertEquals(2, unsafe.code());
        assertTrue(unsafe.error().contains("Set OpenAPI variables before running"));
    }

    private Path specification() throws Exception {
        Path path = temporary.resolve("spec.json");
        Files.writeString(path, SPEC);
        return path;
    }

    private record Run(int code, String output, String error) { }
    private Run run(String... arguments) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream(), error = new ByteArrayOutputStream();
        PrintStream oldOutput = System.out, oldError = System.err;
        try (PrintStream out = new PrintStream(output, true, StandardCharsets.UTF_8);
             PrintStream err = new PrintStream(error, true, StandardCharsets.UTF_8)) {
            System.setOut(out);
            System.setErr(err);
            int code = new CommandLine(new BypassFuzzerCli()).execute(arguments);
            return new Run(code, output.toString(StandardCharsets.UTF_8), error.toString(StandardCharsets.UTF_8));
        } finally { System.setOut(oldOutput); System.setErr(oldError); }
    }
}
