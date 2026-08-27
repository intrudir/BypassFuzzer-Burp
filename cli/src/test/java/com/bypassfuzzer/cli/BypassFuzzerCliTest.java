package com.bypassfuzzer.cli;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
}
