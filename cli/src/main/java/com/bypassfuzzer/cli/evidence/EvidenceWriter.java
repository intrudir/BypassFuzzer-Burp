package com.bypassfuzzer.cli.evidence;

import com.bypassfuzzer.core.http.HttpHeader;
import com.bypassfuzzer.core.http.HttpRequestData;
import com.bypassfuzzer.core.http.HttpResponseData;
import com.bypassfuzzer.core.scan.PlannedRequest;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

public final class EvidenceWriter implements AutoCloseable {
    private static final Set<String> SECRET_HEADERS = Set.of("authorization", "proxy-authorization", "cookie",
        "set-cookie", "x-api-key", "api-key", "x-auth-token");
    private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();
    private final Path root;
    private final Path requests;
    private final Path responses;
    private final BufferedWriter jsonl;
    private final boolean redact;
    private final AtomicLong sequence = new AtomicLong();
    private final String runId;

    public EvidenceWriter(Path root, String runId, boolean redact, Map<String, Object> effectiveConfig) throws IOException {
        this.root = root.toAbsolutePath().normalize();
        this.runId = runId;
        this.redact = redact;
        this.requests = this.root.resolve("requests");
        this.responses = this.root.resolve("responses");
        Files.createDirectories(requests);
        Files.createDirectories(responses);
        secureDirectory(this.root);
        secureDirectory(requests);
        secureDirectory(responses);
        writeJsonAtomic(this.root.resolve("run.json"), Map.of(
            "schemaVersion", 1,
            "runId", runId,
            "startedAt", Instant.now().toString(),
            "effectiveConfig", effectiveConfig == null ? Map.of() : (redact ? redactConfig(effectiveConfig) : effectiveConfig)
        ));
        Path results = this.root.resolve("results.jsonl");
        this.jsonl = Files.newBufferedWriter(results, StandardCharsets.UTF_8);
        secureFile(results);
    }

    public synchronized Map<String, Object> write(String mode, String targetKey, PlannedRequest planned,
                                                   HttpResponseData response, Throwable error, String signal,
                                                   int retryAttempt) throws IOException {
        long number = sequence.incrementAndGet();
        String stem = String.format("%06d", number);
        Path requestFile = requests.resolve(stem + "-request.raw");
        Files.write(requestFile, rawRequest(planned.request()).getBytes(StandardCharsets.ISO_8859_1));
        secureFile(requestFile);
        String responseRef = null;
        if (response != null) {
            Path responseFile = responses.resolve(stem + "-response.raw");
            Files.write(responseFile, rawResponse(response));
            secureFile(responseFile);
            responseRef = relative(responseFile);
        }
        Map<String, Object> record = new LinkedHashMap<>();
        record.put("schemaVersion", 1);
        record.put("runId", runId);
        record.put("sequence", number);
        record.put("timestamp", Instant.now().toString());
        record.put("mode", mode);
        record.put("target", targetKey);
        record.put("protocol", response == null ? planned.request().protocol().id() : response.protocol().id());
        record.put("family", planned.family());
        record.put("payload", planned.payload());
        record.put("encoding", planned.encoding());
        record.put("baseline", planned.baseline());
        record.put("signal", signal);
        record.put("retryAttempt", retryAttempt);
        record.put("requestRef", relative(requestFile));
        record.put("responseRef", responseRef);
        record.put("status", response == null ? null : response.statusCode());
        record.put("length", response == null ? null : response.body().length);
        record.put("contentType", response == null ? null : firstHeader(response, "content-type"));
        record.put("durationMillis", response == null ? null : response.durationMillis());
        record.put("error", error == null ? null : error.getClass().getSimpleName() + ": " + safeMessage(error));
        String line = gson.toJson(record);
        jsonl.write(line);
        jsonl.newLine();
        jsonl.flush();
        System.out.println(line);
        return record;
    }

    public synchronized void summary(Map<String, Object> summary) throws IOException {
        writeJsonAtomic(root.resolve("summary.json"), summary);
    }

    public Path root() { return root; }
    public long count() { return sequence.get(); }

    private String rawRequest(HttpRequestData request) {
        HttpRequestData stored = request;
        if (redact) {
            for (HttpHeader header : request.headers()) {
                if (SECRET_HEADERS.contains(header.name().toLowerCase())) stored = stored.upsertHeader(header.name(), "[REDACTED]");
            }
        }
        return stored.toRaw();
    }

    private byte[] rawResponse(HttpResponseData response) {
        StringBuilder head = new StringBuilder(response.protocol() == com.bypassfuzzer.core.http.HttpProtocol.HTTP_2 ? "HTTP/2" : "HTTP/1.1")
            .append(' ').append(response.statusCode()).append("\r\n");
        for (HttpHeader header : response.headers()) {
            String value = redact && SECRET_HEADERS.contains(header.name().toLowerCase()) ? "[REDACTED]" : header.value();
            head.append(header.name()).append(": ").append(value).append("\r\n");
        }
        head.append("\r\n");
        byte[] prefix = head.toString().getBytes(StandardCharsets.ISO_8859_1);
        byte[] body = response.body();
        byte[] output = java.util.Arrays.copyOf(prefix, prefix.length + body.length);
        System.arraycopy(body, 0, output, prefix.length, body.length);
        return output;
    }

    private String firstHeader(HttpResponseData response, String name) {
        return response.headers().stream().filter(header -> header.name().equalsIgnoreCase(name)).map(HttpHeader::value).findFirst().orElse("");
    }

    private String relative(Path path) { return root.relativize(path).toString().replace('\\', '/'); }
    private String safeMessage(Throwable error) { return error.getMessage() == null ? "" : error.getMessage(); }

    @SuppressWarnings("unchecked")
    private Object redactConfig(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> output = new LinkedHashMap<>();
            map.forEach((key, nested) -> {
                String name = String.valueOf(key);
                String lower = name.toLowerCase();
                if (lower.contains("authorization") || lower.contains("cookie") || lower.contains("token") || lower.contains("api-key")) {
                    output.put(name, "[REDACTED]");
                } else if (name.equals("proxy") && nested != null) {
                    output.put(name, redactProxy(String.valueOf(nested)));
                } else if (name.equals("headers") && nested instanceof Iterable<?> headers) {
                    java.util.List<String> redactedHeaders = new java.util.ArrayList<>();
                    for (Object header : headers) {
                        String text = String.valueOf(header);
                        int colon = text.indexOf(':');
                        String headerName = colon < 0 ? text : text.substring(0, colon);
                        redactedHeaders.add(SECRET_HEADERS.contains(headerName.trim().toLowerCase()) ? headerName + ": [REDACTED]" : text);
                    }
                    output.put(name, redactedHeaders);
                } else output.put(name, redactConfig(nested));
            });
            return output;
        }
        if (value instanceof Iterable<?> iterable) {
            java.util.List<Object> output = new java.util.ArrayList<>();
            iterable.forEach(item -> output.add(redactConfig(item)));
            return output;
        }
        return value;
    }

    private String redactProxy(String value) {
        try {
            java.net.URI uri = java.net.URI.create(value);
            if (uri.getRawUserInfo() == null) return value;
            return new java.net.URI(uri.getScheme(), "[REDACTED]", uri.getHost(), uri.getPort(),
                uri.getPath(), uri.getQuery(), uri.getFragment()).toString();
        } catch (Exception ignored) {
            return "[REDACTED]";
        }
    }

    private void writeJsonAtomic(Path destination, Object value) throws IOException {
        Path temporary = destination.resolveSibling(destination.getFileName() + ".tmp");
        Files.writeString(temporary, gson.toJson(value) + System.lineSeparator(), StandardCharsets.UTF_8);
        secureFile(temporary);
        try { Files.move(temporary, destination, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE); }
        catch (AtomicMoveNotSupportedException ignored) { Files.move(temporary, destination, StandardCopyOption.REPLACE_EXISTING); }
        secureFile(destination);
    }

    private void secureDirectory(Path path) { try { Files.setPosixFilePermissions(path, Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE)); } catch (Exception ignored) {} }
    private void secureFile(Path path) { try { Files.setPosixFilePermissions(path, Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)); } catch (Exception ignored) {} }

    @Override
    public synchronized void close() throws IOException { jsonl.close(); }
}
