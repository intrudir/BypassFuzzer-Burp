package com.bypassfuzzer.cli;

import com.bypassfuzzer.core.filter.*;
import com.bypassfuzzer.core.scan.ResultView;
import com.google.gson.*;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.Callable;

/** File/terminal counterpart of the master's results filtering, inspection and export workspace. */
@Command(name = "results", mixinStandardHelpOptions = true, description = "Filter or export retained evidence with Burp's result filters.")
public final class ResultsCommand implements Callable<Integer> {
    @Option(names = "--input", required = true, description = "Evidence directory or results.jsonl.") Path input;
    @Option(names = "--output", description = "Output file (default stdout).") Path output;
    @Option(names = "--format", description = "tsv, jsonl, hosts, or payloads.") String format = "tsv";
    @Option(names = "--hide-status", split = ",") Set<Integer> hiddenStatuses = Set.of();
    @Option(names = "--show-status", split = ",") Set<Integer> shownStatuses = Set.of();
    @Option(names = "--hide-length", split = ",") Set<Integer> hiddenLengths = Set.of();
    @Option(names = "--show-length", split = ",") Set<Integer> shownLengths = Set.of();
    @Option(names = "--min-length") Integer minLength;
    @Option(names = "--max-length") Integer maxLength;
    @Option(names = "--content-type") String contentType;
    @Option(names = "--host-contains") String host;
    @Option(names = "--payload-contains") String payload;
    @Option(names = "--signal-contains") String signal;
    @Option(names = "--signal-regex") boolean signalRegex;
    @Option(names = "--response-contains") String response;
    @Option(names = "--response-regex") boolean responseRegex;
    @Option(names = "--invert-response-match") boolean inverted;
    @Option(names = "--show-calibration", description = "Include calibration control rows (hidden by default; raw scan evidence is retained).") boolean showCalibration;
    @Option(names = "--smart-repeats", description = "Show the first N results per status/length/content-type pattern.") Integer repeats;

    @Override public Integer call() throws Exception {
        if (!Set.of("tsv", "jsonl", "hosts", "payloads").contains(format))
            throw new IllegalArgumentException("Format must be tsv, jsonl, hosts, or payloads");
        Path file = Files.isDirectory(input) ? input.resolve("results.jsonl") : input;
        Path directory = file.toRealPath().getParent();
        FilterConfig config = new FilterConfig();
        config.setManualFilterEnabled(true);
        config.setShowCalibrationRequests(showCalibration);
        config.setHiddenStatusCodes(hiddenStatuses); config.setShownStatusCodes(shownStatuses);
        config.setHiddenContentLengths(hiddenLengths); config.setShownContentLengths(shownLengths);
        config.setMinContentLength(minLength); config.setMaxContentLength(maxLength);
        config.setContentTypeFilter(contentType); config.setHostContainsFilter(host);
        config.setPayloadContainsFilter(payload); config.setSignalContainsFilter(signal);
        config.setSignalContainsRegex(signalRegex); config.setResponseContainsFilter(response);
        config.setResponseContainsRegex(responseRegex); config.setResponseMatchInverted(inverted);
        if (repeats != null) { config.setSmartFilterEnabled(true); config.setSmartFilterRepeats(repeats); }
        var manual = new ManualFilter(config);
        var smart = new SmartFilter(config);
        Writer sink = output == null ? new OutputStreamWriter(System.out, StandardCharsets.UTF_8)
            : Files.newBufferedWriter(output, StandardCharsets.UTF_8);
        if (output != null) try { Files.setPosixFilePermissions(output, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")); }
            catch (UnsupportedOperationException ignored) { }
        var unique = new LinkedHashSet<String>();
        try {
            Path summary = directory.resolve("summary.json");
            if (format.equals("hosts") && Files.isRegularFile(summary)) {
                JsonObject meta = JsonParser.parseString(Files.readString(summary)).getAsJsonObject();
                if (meta.has("completedHosts")) {
                    for (var value : meta.getAsJsonArray("completedHosts")) sink.write(value.getAsString() + "\n");
                    return 0;
                }
            }
            if (format.equals("tsv")) sink.write("Target\tFamily\tPayload\tEncoding\tSignal\tStatus\tLength\tContent-Type\tRequest\tResponse\n");
            try (var lines = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                String line;
                while ((line = lines.readLine()) != null) {
                    if (line.isBlank()) continue;
                    JsonObject data = JsonParser.parseString(line).getAsJsonObject();
                    var view = new StoredResult(data, directory);
                    smart.track(view);
                    if (view.getControlRole().isCalibration() && !config.isShowCalibrationRequests()) continue;
                    if (!smart.shouldShow(view) || !manual.shouldShow(view)) continue;
                    if (format.equals("jsonl")) sink.write(data + "\n");
                    else if (format.equals("payloads") || format.equals("hosts")) {
                        String value = format.equals("hosts") ? view.getRequestHost() : view.getPayload();
                        if (value != null && unique.add(value)) sink.write(cell(value) + "\n");
                    } else {
                        var fields = List.of("target", "family", "payload", "encoding", "signal", "status", "length", "contentType", "requestRef", "responseRef");
                        sink.write(fields.stream().map(k -> cell(view.text(k))).collect(java.util.stream.Collectors.joining("\t")) + "\n");
                    }
                }
            }
        } finally { sink.flush(); if (output != null) sink.close(); }
        return 0;
    }

    private static String cell(String text) { return text == null ? "" : text.replace('\t', ' ').replace('\r', ' ').replace('\n', ' '); }
    private record StoredResult(JsonObject data, Path directory) implements ResultView {
        String text(String key) { return !data.has(key) || data.get(key).isJsonNull() ? "" : data.get(key).getAsString(); }
        public com.bypassfuzzer.core.scan.ControlRole getControlRole() {
            try { return com.bypassfuzzer.core.scan.ControlRole.valueOf(text("controlRole")); }
            catch (IllegalArgumentException unknownOrLegacyRole) { return com.bypassfuzzer.core.scan.ControlRole.NONE; }
        }
        public int getStatusCode() { return text("status").isBlank() ? 0 : Integer.parseInt(text("status")); }
        public int getContentLength() { return text("length").isBlank() ? 0 : Integer.parseInt(text("length")); }
        public String getContentType() { return text("contentType"); }
        public String getPayload() { return text("payload"); }
        public String getSignal() { return text("signal"); }
        public String getRequestHost() {
            String request = read("requestRef");
            if (request == null) return "";
            String target = text("target");
            int scheme = target.indexOf("://");
            if (scheme >= 0) {
                int start = target.lastIndexOf(' ', scheme);
                try { return java.net.URI.create(target.substring(start + 1)).getHost(); }
                catch (IllegalArgumentException ignored) { }
            }
            return "";
        }
        public String getResponseText() { return read("responseRef"); }
        private String read(String key) {
            String ref = text(key);
            if (ref.isBlank()) return null;
            try {
                Path file = directory.resolve(ref).toRealPath();
                if (!file.startsWith(directory)) throw new IllegalArgumentException("Evidence reference escapes its directory");
                return Files.readString(file, StandardCharsets.ISO_8859_1);
            } catch (IOException error) { throw new UncheckedIOException(error); }
        }
    }
}
