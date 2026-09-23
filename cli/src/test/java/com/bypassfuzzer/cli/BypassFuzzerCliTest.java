package com.bypassfuzzer.cli;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.bypassfuzzer.core.scan.ResponseGuidedIdorPlanner;
import com.bypassfuzzer.core.scan.IdorPlanner;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BypassFuzzerCliTest {
    @TempDir Path temporary;

    @Test
    void bypassCommandRunsEndToEndAndFlagsOverrideYaml() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/private", exchange -> {
            boolean mutated = exchange.getRequestHeaders().containsKey("Accept-Application");
            byte[] body = (mutated ? "allowed" : "blocked").getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("X-Test-Result", mutated ? "bypass" : "baseline");
            exchange.sendResponseHeaders(mutated ? 200 : 403, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        try {
            Path request = temporary.resolve("request.raw");
            Files.writeString(request, "GET /private HTTP/1.1\r\nHost: fuzzable.example\r\nAuthorization: Bearer secret\r\n\r\n", StandardCharsets.ISO_8859_1);
            Path yaml = temporary.resolve("job.yaml");
            Files.writeString(yaml, "schemaVersion: 1\ntransport:\n  protocol: http2\nevidence:\n  redact: true\n", StandardCharsets.UTF_8);
            Path output = temporary.resolve("evidence");
            int code = new CommandLine(new BypassFuzzerCli()).execute("bypass",
                "--config", yaml.toString(), "--request", request.toString(), "--target-origin",
                "http://127.0.0.1:" + server.getAddress().getPort(), "--protocol", "http1",
                "--families", "header", "--max-probes", "5", "--retry-attempts", "0",
                "--output", output.toString());

            assertEquals(0, code);
            JsonObject summary = JsonParser.parseString(Files.readString(output.resolve("summary.json"))).getAsJsonObject();
            assertEquals("completed", summary.get("state").getAsString());
            assertTrue(summary.get("findings").getAsInt() >= 1);
            assertEquals(6, Files.readAllLines(output.resolve("results.jsonl")).size());
            JsonObject run = JsonParser.parseString(Files.readString(output.resolve("run.json"))).getAsJsonObject();
            assertEquals("http1", run.getAsJsonObject("effectiveConfig").getAsJsonObject("transport").get("protocol").getAsString());
            String storedBaseline = Files.readString(output.resolve("requests/000001-request.raw"), StandardCharsets.ISO_8859_1);
            assertTrue(storedBaseline.contains("Authorization: [REDACTED]"));
        } finally { server.stop(0); }
    }

    @Test
    void collaboratorYamlIsRejectedBeforeRun() throws Exception {
        Path yaml = temporary.resolve("bad.yaml");
        Files.writeString(yaml, "schemaVersion: 1\nbypass:\n  collaborator: true\n", StandardCharsets.UTF_8);
        int code = new CommandLine(new BypassFuzzerCli()).execute("bypass", "--config", yaml.toString());
        assertEquals(2, code);
    }

    @Test
    void idorPreviewShowsSelectedSlotAndUniqueCreateValuesWithoutSending() throws Exception {
        Path request = temporary.resolve("create.raw");
        String body = "{\"name\":\"Attacker\"}";
        Files.writeString(request, "POST /namespaces/619/projects HTTP/1.1\r\nHost: example.invalid\r\n"
            + "Content-Type: application/json\r\nContent-Length: " + body.length() + "\r\n\r\n" + body,
            StandardCharsets.ISO_8859_1);
        ByteArrayOutputStream preview = new ByteArrayOutputStream();
        PrintStream old = System.out;
        try {
            System.setOut(new PrintStream(preview, true, StandardCharsets.UTF_8));
            int code = new CommandLine(new BypassFuzzerCli()).execute("idor", "--preview",
                "--request", request.toString(), "--target-origin", "https://example.invalid",
                "--authorized-id", "619", "--target-id", "620", "--id-location", "path:2",
                "--families", "idor.path.suffix_formats",
                "--unique-json-field", "/name");
            assertEquals(0, code);
        } finally { System.setOut(old); }
        String rendered = preview.toString(StandardCharsets.UTF_8);
        assertTrue(rendered.contains("idor.baseline.control"));
        assertTrue(rendered.contains("idor.baseline.target"));
        assertTrue(rendered.contains("/namespaces/620.json/projects"));
        assertTrue(rendered.contains("Attacker-bf-"));
        assertTrue(rendered.contains("-1") && rendered.contains("-2") && rendered.contains("-3"));
    }

    @Test
    void idorRejectsAmbiguousIdentifierBeforeStartingScan() throws Exception {
        Path request = temporary.resolve("ambiguous.raw");
        Files.writeString(request, "GET /objects/619?id=619 HTTP/1.1\r\nHost: example.invalid\r\n\r\n",
            StandardCharsets.ISO_8859_1);
        Path output = temporary.resolve("no-evidence");
        int code = new CommandLine(new BypassFuzzerCli()).execute("idor",
            "--request", request.toString(), "--target-origin", "https://example.invalid",
            "--authorized-id", "619", "--target-id", "620", "--output", output.toString());
        assertEquals(2, code);
        assertTrue(Files.notExists(output));
    }

    @Test
    void idorPreviewRequiresExplicitOptInForUnselectedIdentifierValues() throws Exception {
        Path request = temporary.resolve("numeric.raw");
        Files.writeString(request, "GET /projects/7651/stats?locale=en_US HTTP/1.1\r\n"
            + "Host: example.invalid\r\n\r\n", StandardCharsets.ISO_8859_1);
        ByteArrayOutputStream preview = new ByteArrayOutputStream();
        ByteArrayOutputStream warnings = new ByteArrayOutputStream();
        PrintStream originalOut = System.out;
        PrintStream originalErr = System.err;
        try {
            System.setOut(new PrintStream(preview, true, StandardCharsets.UTF_8));
            System.setErr(new PrintStream(warnings, true, StandardCharsets.UTF_8));
            String[] arguments = {"idor", "--preview", "--request", request.toString(),
                "--target-origin", "https://example.invalid", "--authorized-id", "7651",
                "--target-id", "7648", "--id-location", "path:2"};
            assertEquals(0, new CommandLine(new BypassFuzzerCli()).execute(arguments));
            assertFalse(preview.toString(StandardCharsets.UTF_8).contains("/projects/7649/stats"));
            assertFalse(preview.toString(StandardCharsets.UTF_8).contains(IdorPlanner.NUMERIC_PIVOTS_FAMILY));
            assertFalse(preview.toString(StandardCharsets.UTF_8).contains(IdorPlanner.SPECIAL_IDENTIFIER_VALUES_FAMILY));
            assertTrue(preview.toString(StandardCharsets.UTF_8).contains("LF U+000A | id1 → id2"));
            assertTrue(preview.toString(StandardCharsets.UTF_8)
                .contains("/projects/7651%0A7648/stats?locale=en_US"));
            assertTrue(warnings.toString(StandardCharsets.UTF_8)
                .contains("Paired control separators: 172/172 planned"));
            assertTrue(preview.toString(StandardCharsets.UTF_8).split("=== ", -1).length - 1 > 202);
            for (String id : java.util.List.of("0", "1", "-1"))
                assertFalse(preview.toString(StandardCharsets.UTF_8).contains("/projects/" + id + "/stats"));
            assertFalse(warnings.toString(StandardCharsets.UTF_8).contains("DANGEROUS"));

            for (String family : java.util.List.of(IdorPlanner.NUMERIC_PIVOTS_FAMILY,
                IdorPlanner.SPECIAL_IDENTIFIER_VALUES_FAMILY)) {
                preview.reset();
                warnings.reset();
                String[] optedIn = java.util.Arrays.copyOf(arguments, arguments.length + 2);
                optedIn[arguments.length] = "--families";
                optedIn[arguments.length + 1] = family;
                assertEquals(0, new CommandLine(new BypassFuzzerCli()).execute(optedIn));
                assertTrue(preview.toString(StandardCharsets.UTF_8).contains(family));
                assertTrue(warnings.toString(StandardCharsets.UTF_8).contains("DANGEROUS: " + family));
            }
            warnings.reset();
            String[] capped = java.util.Arrays.copyOf(arguments, arguments.length + 2);
            capped[arguments.length] = "--max-probes";
            capped[arguments.length + 1] = "10";
            assertEquals(2, new CommandLine(new BypassFuzzerCli()).execute(capped));
            assertTrue(warnings.toString(StandardCharsets.UTF_8).contains("IDOR no longer supports --max-probes"));
            Path cappedJob = temporary.resolve("idor-cap.yaml");
            Files.writeString(cappedJob, "schemaVersion: 1\nexecution:\n  maxProbes: 10\n");
            warnings.reset();
            String[] configuredCap = java.util.Arrays.copyOf(arguments, arguments.length + 2);
            configuredCap[arguments.length] = "--config";
            configuredCap[arguments.length + 1] = cappedJob.toString();
            assertEquals(2, new CommandLine(new BypassFuzzerCli()).execute(configuredCap));
            assertTrue(warnings.toString(StandardCharsets.UTF_8).contains("execution.maxProbes"));
        } finally {
            System.setOut(originalOut);
            System.setErr(originalErr);
        }
    }

    @Test
    void headerControlPreviewRequiresHttp1Protocol() throws Exception {
        Path request = temporary.resolve("header-id.raw");
        Files.writeString(request, "GET /items HTTP/1.1\r\nHost: example.invalid\r\n"
            + "X-Object-Id: 7651\r\n\r\n", StandardCharsets.ISO_8859_1);
        ByteArrayOutputStream preview = new ByteArrayOutputStream();
        ByteArrayOutputStream notes = new ByteArrayOutputStream();
        PrintStream originalOut = System.out;
        PrintStream originalErr = System.err;
        try {
            System.setOut(new PrintStream(preview, true, StandardCharsets.UTF_8));
            System.setErr(new PrintStream(notes, true, StandardCharsets.UTF_8));
            String[] arguments = {"idor", "--preview", "--request", request.toString(),
                "--target-origin", "https://example.invalid", "--authorized-id", "7651",
                "--target-id", "7648", "--id-location", "header:x-object-id#0"};
            assertEquals(0, new CommandLine(new BypassFuzzerCli()).execute(arguments));
            assertFalse(preview.toString(StandardCharsets.UTF_8).contains("7651\t7648"));
            assertTrue(notes.toString(StandardCharsets.UTF_8).contains("may negotiate HTTP/2"));

            preview.reset();
            notes.reset();
            String[] http1 = java.util.Arrays.copyOf(arguments, arguments.length + 2);
            http1[arguments.length] = "--protocol";
            http1[arguments.length + 1] = "http1";
            assertEquals(0, new CommandLine(new BypassFuzzerCli()).execute(http1));
            assertTrue(preview.toString(StandardCharsets.UTF_8).contains("7651\t7648"));
            assertTrue(notes.toString(StandardCharsets.UTF_8)
                .contains("Paired control separators: 2/2 planned"));
        } finally {
            System.setOut(originalOut);
            System.setErr(originalErr);
        }
    }

    @Test
    void responseGuidedIdorUsesTheSamePreviewAndLivePlanner() throws Exception {
        Path request = temporary.resolve("response-guided.raw");
        Files.writeString(request, "POST /accounts/11/items HTTP/1.1\r\nHost: example.invalid\r\n"
            + "Content-Type: application/json\r\n\r\n{\"name\":\"sample\"}", StandardCharsets.ISO_8859_1);
        Path sample = temporary.resolve("baseline.raw");
        Files.writeString(sample, "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n"
            + "{\"groupRef\":11,\"links\":[{\"ownerId\":11}]}", StandardCharsets.ISO_8859_1);
        ByteArrayOutputStream preview = new ByteArrayOutputStream();
        PrintStream old = System.out;
        try {
            System.setOut(new PrintStream(preview, true, StandardCharsets.UTF_8));
            assertEquals(0, new CommandLine(new BypassFuzzerCli()).execute("idor", "--preview",
                "--request", request.toString(), "--target-origin", "https://example.invalid",
                "--authorized-id", "11", "--target-id", "12", "--id-location", "path:2",
                "--families", ResponseGuidedIdorPlanner.FAMILY, "--baseline-response", sample.toString()));
        } finally { System.setOut(old); }
        String rendered = preview.toString(StandardCharsets.UTF_8);
        assertTrue(rendered.contains("authorized path / target body | /groupRef | exact"));
        assertTrue(rendered.contains("\"groupRef\":12"));
        assertTrue(rendered.contains("/accounts/12/items"));

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/accounts", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            boolean target = exchange.getRequestURI().getPath().contains("/12/");
            int status = target && !body.contains("groupRef") ? 403 : 201;
            String result = status == 403 ? "{\"error\":\"denied\"}"
                : body.contains("\"groupRef\":12") || target ? "{\"groupRef\":12}" : "{\"groupRef\":11}";
            byte[] bytes = result.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        try {
            Path output = temporary.resolve("guided-evidence");
            assertEquals(0, new CommandLine(new BypassFuzzerCli()).execute("idor",
                "--request", request.toString(), "--target-origin",
                "http://127.0.0.1:" + server.getAddress().getPort(),
                "--authorized-id", "11", "--target-id", "12", "--id-location", "path:2",
                "--families", ResponseGuidedIdorPlanner.FAMILY,
                "--retry-attempts", "0", "--protocol", "http1", "--output", output.toString()));
            var rows = Files.readAllLines(output.resolve("results.jsonl"));
            assertTrue(rows.size() >= 4);
            assertTrue(rows.stream().anyMatch(row -> row.contains("MASS_ASSIGNMENT_CANDIDATE")));
            assertTrue(rows.stream().anyMatch(row -> row.contains("IDOR_CANDIDATE")));
            assertTrue(rows.stream().anyMatch(row -> row.contains("/groupRef")));

            Path defaultOutput = temporary.resolve("guided-default-evidence");
            assertEquals(0, new CommandLine(new BypassFuzzerCli()).execute("idor",
                "--request", request.toString(), "--target-origin",
                "http://127.0.0.1:" + server.getAddress().getPort(),
                "--authorized-id", "11", "--target-id", "12", "--id-location", "path:2",
                "--retry-attempts", "0", "--protocol", "http1",
                "--output", defaultOutput.toString()));
            assertTrue(Files.readAllLines(defaultOutput.resolve("results.jsonl")).stream()
                .anyMatch(row -> row.contains("MASS_ASSIGNMENT_CANDIDATE")));
        } finally { server.stop(0); }
    }
}
