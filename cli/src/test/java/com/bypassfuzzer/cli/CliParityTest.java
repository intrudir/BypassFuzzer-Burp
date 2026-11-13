package com.bypassfuzzer.cli;

import com.google.gson.*;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

class CliParityTest {
    @Test void resultsExportRejectsItsInputAndFileAliasesBeforeTruncating() throws Exception {
        Path directory = temporary.resolve("retained"); Files.createDirectory(directory);
        Path input = directory.resolve("results.jsonl");
        String original = "{\"schemaVersion\":1,\"payload\":\"keep me\",\"status\":403,\"length\":0}\n";
        Files.writeString(input, original);
        var aliases = new java.util.ArrayList<Path>(List.of(input, directory.resolve("../retained/results.jsonl")));
        try { aliases.add(Files.createLink(directory.resolve("hardlink.jsonl"), input)); }
        catch (UnsupportedOperationException | java.nio.file.FileSystemException unavailable) { }
        try { aliases.add(Files.createSymbolicLink(directory.resolve("symlink.jsonl"), input)); }
        catch (UnsupportedOperationException | java.nio.file.FileSystemException unavailable) { }
        for (Path alias : aliases) {
            Run result = run("results", "--input", directory.toString(), "--output", alias.toString(), "--format", "jsonl");
            assertEquals(2, result.code(), alias.toString());
            assertEquals(original, Files.readString(input));
        }
        Path export = directory.resolve("filtered.jsonl");
        assertEquals(0, run("results", "--input", input.toString(), "--output", export.toString(), "--format", "jsonl").code());
        assertTrue(Files.readString(export).contains("keep me"));
        assertEquals(original, Files.readString(input));
    }

    @TempDir Path temporary;
    private record Run(int code, String output) { }
    private static String[] legacyArgs(String[] args) {
        if (args.length == 0 || !(args[0].equals("bypass") || args[0].equals("sweep"))) return args;
        var legacy = new java.util.ArrayList<String>(java.util.List.of(args));
        legacy.add("--no-wildcard-calibration"); return legacy.toArray(String[]::new);
    }
    private Run run(String... args) {
        var bytes = new ByteArrayOutputStream();
        PrintStream saved = System.out;
        try {
            System.setOut(new PrintStream(bytes, true, StandardCharsets.UTF_8));
            return new Run(new CommandLine(new BypassFuzzerCli()).execute(legacyArgs(args)), bytes.toString(StandardCharsets.UTF_8));
        } finally { System.setOut(saved); }
    }
    private Path request(String name, String path, String headers) throws IOException {
        Path file = temporary.resolve(name);
        Files.writeString(file, "GET " + path + " HTTP/1.1\r\nHost: example.com\r\n" + headers + "\r\n", StandardCharsets.ISO_8859_1);
        return file;
    }
    private String origin(HttpServer server) { return "http://127.0.0.1:" + server.getAddress().getPort(); }
    private JsonObject summary(Path output) throws IOException {
        return JsonParser.parseString(Files.readString(output.resolve("summary.json"))).getAsJsonObject();
    }

    @Test void calibrationRowsAreOptionalWithoutChangingRetainedEvidenceOrSmartSlots() throws Exception {
        Path input = temporary.resolve("calibration-results.jsonl");
        var roles = java.util.Arrays.asList("WILDCARD", "WILDCARD", "NONE", "ORIGINAL", "AUTHORIZED", "TARGET", "FUTURE_ROLE", null);
        StringBuilder data = new StringBuilder();
        for (int index = 0; index < roles.size(); index++) {
            var row = new JsonObject(); row.addProperty("schemaVersion", 1);
            row.addProperty("payload", "row-" + index); row.addProperty("status", index == 1 ? 0 : 404);
            row.addProperty("length", 0); row.addProperty("contentType", "");
            if (roles.get(index) != null) row.addProperty("controlRole", roles.get(index));
            data.append(row).append('\n');
        }
        Files.writeString(input, data);
        Run hidden = run("results", "--input", input.toString(), "--format", "jsonl");
        assertEquals(0, hidden.code()); assertEquals(6, hidden.output().lines().count());
        assertFalse(hidden.output().contains("WILDCARD"));
        Run shown = run("results", "--input", input.toString(), "--format", "jsonl", "--show-calibration");
        assertEquals(0, shown.code()); assertEquals(8, shown.output().lines().count());
        Run smart = run("results", "--input", input.toString(), "--format", "jsonl", "--show-calibration", "--smart-repeats", "1");
        assertEquals(0, smart.code()); assertEquals(3, smart.output().lines().count());
        assertTrue(smart.output().contains("row-2"));
        assertEquals(data.toString(), Files.readString(input));
    }

    @Test void fullSweepAndTargetedBypassAreUncappedByDefault() throws Exception {
        Path request = request("catalog.raw", "/private/reports/quarterly?id=alice", "");
        for (String mode : List.of("sweep", "bypass")) {
            var args = new ArrayList<>(List.of(mode, "--preview", "--request", request.toString(),
                "--target-origin", "https://example.com"));
            if (mode.equals("sweep")) args.addAll(List.of("--payload-set", "all"));
            Run result = run(args.toArray(String[]::new));
            assertEquals(0, result.code());
            assertTrue(result.output().lines().filter(l -> l.startsWith("=== ")).count() > 10_000);
            assertTrue(result.output().contains("Protocol: HTTP/0.9"));
        }
    }

    @Test void protectedDuplicateHeadersAndPerMutationUserAgentsReachTheSocket() throws Exception {
        var headers = new CopyOnWriteArrayList<Map<String, List<String>>>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            var copy = new TreeMap<String, List<String>>(String.CASE_INSENSITIVE_ORDER);
            exchange.getRequestHeaders().forEach((k, v) -> copy.put(k, List.copyOf(v)));
            headers.add(copy);
            exchange.sendResponseHeaders(200, 1); exchange.getResponseBody().write('x'); exchange.close();
        });
        server.start();
        try {
            Path file = request("headers.raw", "/private", "");
            Run result = run("bypass", "--request", file.toString(), "--target-origin", origin(server),
                "--families", "header", "--max-probes", "1", "--retry-attempts", "0", "--protocol", "http1",
                "--header", "X-Audit: first", "--header", "X-Audit: second",
                "--header", "Accept-Application: configured", "--user-agent-mode", "synthetic",
                "--user-agent-seed", "42", "--output", temporary.resolve("headers-out").toString());
            assertEquals(0, result.code());
            assertEquals(2, headers.size());
            assertEquals(List.of("first", "second"), headers.get(0).get("X-Audit"));
            assertEquals(List.of("first", "second"), headers.get(1).get("X-Audit"));
            assertTrue(headers.get(1).get("Accept-Application").contains("configured"));
            assertEquals(2, headers.get(1).get("Accept-Application").size());
            assertNotEquals(headers.get(0).get("User-Agent"), headers.get(1).get("User-Agent"));
        } finally { server.stop(0); }
    }

    @Test void authenticatedSweepStripsSelectedCredentialsAndSkipsPublicEndpoints() throws Exception {
        var authentication = new CopyOnWriteArrayList<String>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            authentication.add(Objects.toString(exchange.getRequestHeaders().getFirst("Authorization"), "absent"));
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, 2); exchange.getResponseBody().write("{}".getBytes()); exchange.close();
        });
        server.start();
        try {
            Path file = request("auth.raw", "/public", "Authorization: Bearer owned\r\n");
            Path output = temporary.resolve("auth-out");
            Run result = run("sweep", "--request", file.toString(), "--target-origin", origin(server),
                "--sweep-mode", "authenticated", "--families", "Header", "--protocol", "http1", "--output", output.toString());
            assertEquals(0, result.code());
            assertEquals(List.of("Bearer owned", "absent"), authentication);
            assertEquals(1, summary(output).get("skippedPublicEndpoints").getAsInt());
            assertTrue(Files.readString(output.resolve("results.jsonl")).contains("LIKELY PUBLIC"));
        } finally { server.stop(0); }
    }

    @Test void customHostPortsAreInTheActualPreview() throws Exception {
        Path file = request("ports.raw", "/private", "");
        Run result = run("sweep", "--preview", "--request", file.toString(), "--target-origin", "https://example.com",
            "--families", "Host Parsing", "--host-ports", "8443");
        assertEquals(0, result.code());
        assertTrue(result.output().contains("Host: example.com:8443:443"));
    }

    @Test void retryPackageReplaysOnlyTheSavedMutationAndPreservesItsMetadata() throws Exception {
        var received = new CopyOnWriteArrayList<String>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            received.add(exchange.getRequestMethod() + " " + exchange.getRequestURI() + " "
                + new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            exchange.sendResponseHeaders(200, 1); exchange.getResponseBody().write('x'); exchange.close();
        });
        server.start();
        try {
            String raw = "POST /saved?x=1 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello";
            var entry = new com.bypassfuzzer.core.input.RetryPackageEntry("Saved target", "Saved mutation", "Encoding", "URL encoded",
                2, raw, origin(server) + "/saved?x=1", "POST", "HTTP_1", "Saved mutation");
            Path file = temporary.resolve("retry.json");
            Files.writeString(file, new Gson().toJson(new com.bypassfuzzer.core.input.RetryPackage("1", "bypassfuzzer-retry-queue", List.of(entry))));
            Path output = temporary.resolve("retry-out");
            Run result = run("sweep", "--retry-package", file.toString(), "--payload-set", "all", "--retry-attempts", "0", "--output", output.toString());
            assertEquals(0, result.code());
            assertEquals(List.of("POST /saved?x=1 hello"), received);
            JsonObject record = JsonParser.parseString(Files.readString(output.resolve("results.jsonl")).trim()).getAsJsonObject();
            assertEquals("Saved mutation", record.get("payload").getAsString());
            assertEquals("Encoding", record.get("family").getAsString());
            assertEquals("URL encoded", record.get("encoding").getAsString());
            assertEquals(3, record.get("retryAttempt").getAsInt());
        } finally { server.stop(0); }
    }

    @Test void outOfBandPayloadsUseTheSharedHeaderInventory() throws Exception {
        Path file = request("oob.raw", "/private", "");
        Run result = run("bypass", "--preview", "--request", file.toString(), "--target-origin", "https://example.com",
            "--families", "header", "--oob-domain", "owned-callback.example");
        assertEquals(0, result.code());
        assertTrue(result.output().contains("http://owned-callback.example"));
        assertTrue(result.output().contains("https://owned-callback.example"));
    }

    @Test void explicitUrlHostDoesNotInvokeAnUnusedGeneratorAndBypassValidatesItsSource() throws Exception {
        Path file = request("source.raw", "/redirect?next={INJECT}", "");
        Path missingGenerator = temporary.resolve("missing-generator");
        assertEquals(0, run("url-validation", "--preview", "--request", file.toString(),
            "--target-origin", "https://example.com", "--attacker-host", "owned.example",
            "--oob-generator", missingGenerator.toString()).code());
        Path output = temporary.resolve("bad-generator-out");
        assertEquals(2, run("bypass", "--request", file.toString(), "--target-origin", "https://example.com",
            "--families", "header", "--oob-generator", missingGenerator.toString(), "--output", output.toString()).code());
        assertFalse(Files.exists(output));
    }

    @Test void contentTypeSignalAndResultFiltersFollowTheBurpRules() throws Exception {
        var count = new AtomicInteger();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", count.getAndIncrement() == 0 ? "text/plain" : "application/json");
            exchange.sendResponseHeaders(200, 1); exchange.getResponseBody().write('x'); exchange.close();
        });
        server.start();
        try {
            Path file = request("classify.raw", "/private", "");
            Path output = temporary.resolve("classify-out");
            assertEquals(0, run("sweep", "--request", file.toString(), "--target-origin", origin(server),
                "--families", "Header", "--max-probes", "2", "--protocol", "http1", "--output", output.toString()).code());
            Run selected = run("results", "--input", output.toString(), "--format", "jsonl", "--signal-contains", "Content-Type");
            assertEquals(0, selected.code());
            assertTrue(selected.output().contains("Content-Type text/plain -"));
            assertEquals(1, selected.output().lines().count());
            assertEquals(0, run("results", "--input", output.toString(), "--format", "jsonl", "--show-status", "403").output().lines().count());
        } finally { server.stop(0); }
    }

    @Test void initialPauseAndStopControlNeverSendARequest() throws Exception {
        var count = new AtomicInteger();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> { count.incrementAndGet(); exchange.sendResponseHeaders(200, -1); exchange.close(); });
        server.start();
        var worker = Executors.newSingleThreadExecutor();
        try {
            Path control = temporary.resolve("control.txt");
            Files.writeString(control, "pause");
            Path file = request("pause.raw", "/private", "");
            Path output = temporary.resolve("pause-out");
            Future<Integer> run = worker.submit(() -> new CommandLine(new BypassFuzzerCli()).execute("bypass", "--no-wildcard-calibration",
                "--request", file.toString(), "--target-origin", origin(server), "--families", "header",
                "--max-probes", "1", "--control-file", control.toString(), "--output", output.toString()));
            Thread.sleep(300);
            assertEquals(0, count.get());
            Files.writeString(control, "stop");
            assertEquals(0, run.get(5, TimeUnit.SECONDS));
            assertEquals(0, count.get());
            assertEquals("stopped", summary(output).get("state").getAsString());
        } finally { worker.shutdownNow(); server.stop(0); }
    }

    @Test void resumeAndDashboardRateLimitGovernRealSends() throws Exception {
        var times = new CopyOnWriteArrayList<Long>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            times.add(System.nanoTime()); exchange.sendResponseHeaders(200, -1); exchange.close();
        });
        server.start();
        var worker = Executors.newSingleThreadExecutor();
        try {
            Path control = temporary.resolve("resume.txt"); Files.writeString(control, "pause");
            Path file = request("resume.raw", "/private", "");
            Future<Integer> run = worker.submit(() -> new CommandLine(new BypassFuzzerCli()).execute("bypass", "--no-wildcard-calibration",
                "--request", file.toString(), "--target-origin", origin(server), "--protocol", "http1",
                "--families", "header", "--max-probes", "2", "--control-file", control.toString(),
                "--traffic-max-rps", "5", "--output", temporary.resolve("resume-out").toString()));
            Thread.sleep(300); assertTrue(times.isEmpty());
            long resumedAt = System.nanoTime();
            Files.writeString(control, "resume");
            assertEquals(0, run.get(8, TimeUnit.SECONDS));
            assertEquals(3, times.size());
            // Admission precedes connection setup, whose latency can compress arrival gaps.
            // Check the cumulative 5 req/s budget; the governor tests measure admission spacing directly.
            for (int index = 1; index < times.size(); index++)
                assertTrue(times.get(index) - resumedAt >= TimeUnit.MILLISECONDS.toNanos(200L * index - 20L),
                    "Request " + index + " arrived before its post-resume rate budget");
        } finally { worker.shutdownNow(); server.stop(0); }
    }

    @Test void uncappedSweepRejectsAnExplicitCapAndUrlInputsFailPreflight() throws Exception {
        Path file = request("preflight.raw", "/private", "");
        Path output = temporary.resolve("preflight-out");
        assertEquals(2, run("sweep", "--request", file.toString(), "--target-origin", "https://example.com",
            "--payload-set", "all", "--max-probes", "10", "--output", output.toString()).code());
        assertFalse(Files.exists(output));
        assertEquals(2, run("url-validation", "--request", file.toString(), "--target-origin", "https://example.com",
            "--attacker-host", "owned.example", "--output", output.toString()).code());
        assertFalse(Files.exists(output));
    }

    @Test void stoppedExactReplayKeepsEveryUnsentEntry() throws Exception {
        String raw = "GET /saved HTTP/1.1\r\nHost: example.com\r\n\r\n";
        var first = new com.bypassfuzzer.core.input.RetryPackageEntry("Saved", "One", "Header", "raw", 2,
            raw, "https://example.com/saved", "GET", "HTTP_1", "One");
        var second = new com.bypassfuzzer.core.input.RetryPackageEntry("Saved", "Two", "Header", "raw", 3,
            raw, "https://example.com/saved", "GET", "HTTP_1", "Two");
        Path file = temporary.resolve("unsent.json");
        Files.writeString(file, new Gson().toJson(new com.bypassfuzzer.core.input.RetryPackage("1", "bypassfuzzer-retry-queue", List.of(first, second))));
        Path control = temporary.resolve("already-stopped.txt"); Files.writeString(control, "stop");
        Path output = temporary.resolve("unsent-out");
        assertEquals(0, run("sweep", "--retry-package", file.toString(), "--control-file", control.toString(), "--output", output.toString()).code());
        var retained = JsonParser.parseString(Files.readString(output.resolve("retry-queue.json"))).getAsJsonObject().getAsJsonArray("entries");
        assertEquals(2, retained.size());
        assertEquals(2, retained.get(0).getAsJsonObject().get("retryAttempt").getAsInt());
        assertEquals(3, retained.get(1).getAsJsonObject().get("retryAttempt").getAsInt());
        assertEquals(0, summary(output).get("requestsSent").getAsInt());
    }
}
