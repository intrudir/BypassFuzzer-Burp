package com.bypassfuzzer.cli.run;

import com.bypassfuzzer.cli.evidence.EvidenceWriter;
import com.bypassfuzzer.core.http.HttpRequestData;
import com.bypassfuzzer.core.http.RequestTransport;
import com.bypassfuzzer.core.scan.PlannedRequest;
import com.bypassfuzzer.core.scan.ScanEngine;
import com.bypassfuzzer.core.scan.ScanOptions;

import java.io.UncheckedIOException;
import java.util.List;
import java.util.function.Function;

/** CLI evidence adapter for the shared scan engine. */
public final class ScanExecutor {
    public void replay(List<com.bypassfuzzer.core.input.RetryPackageEntry> entries, RequestTransport transport,
        ExecutionOptions options, com.bypassfuzzer.core.http.RequestHeaderPolicy<HttpRequestData> policy,
        EvidenceWriter evidence, RunControl control) throws Exception {
        var settings = new ScanOptions(options.protocol(), options.requestTimeout(), options.globalConcurrency(),
            options.perHostConcurrency(), options.throttleStatusCodes(), options.retryAttempts(), true,
            options.posture(), options.pauseMode(), options.fixedPauseMillis(), false);
        var engine = new ScanEngine(settings);
        var pending = new java.util.concurrent.ConcurrentSkipListMap<Integer, com.bypassfuzzer.core.input.RetryPackageEntry>();
        for (int index = 0; index < entries.size(); index++) pending.put(index, entries.get(index));
        try (var binding = control.bind(engine::pause, engine::resume, engine::stop)) {
        int entryNumber = 0;
        for (var entry : entries) {
            int number = entryNumber++;
            if (!control.continuing()) break;
            var item = entry.planned();
            var base = item.request();
            engine.run("sweep", List.of(base), value -> List.of(item.withRequest(policy.reconcileMutation(base,
                base.withSyncedContentLength().withProtocol(options.protocol() == com.bypassfuzzer.core.http.HttpProtocol.AUTO
                    ? base.protocol() : value.protocol())))), transport, event -> {
                try {
                    int attempt = entry.retryAttempt() + event.retryAttempt() + 1;
                    evidence.write("sweep", entry.targetLabel(), event.planned(), event.response(), event.error(), event.signal(), attempt);
                    if (event.response() == null || options.throttleStatusCodes().contains(event.response().statusCode()))
                        pending.put(number, evidence.retryEntry(event.planned(), attempt));
                    else pending.remove(number);
                } catch (java.io.IOException error) { throw new UncheckedIOException(error); }
            });
        }
        }
        evidence.retryPackage(List.copyOf(pending.values()));
        evidence.summary(java.util.Map.of("schemaVersion", 1, "mode", "sweep", "state", control.stopped() ? "stopped" : "completed",
            "records", evidence.count(), "requestsSent", engine.requestsSent(), "deferredRetries", pending.size()));
    }
    public ScanEngine.Summary run(String mode, List<HttpRequestData> inputs,
                                  Function<HttpRequestData, List<PlannedRequest>> planner,
                                  RequestTransport transport, ExecutionOptions options,
                                  EvidenceWriter evidence) throws Exception {
        try (var control = new RunControl(null, null, null)) {
            return run(mode, inputs, planner, null, transport, options, evidence, control);
        }
    }

    public ScanEngine.Summary run(String mode, List<HttpRequestData> inputs,
                                  Function<HttpRequestData, List<PlannedRequest>> planner,
                                  ScanEngine.PostBaselinePlanner postBaselinePlanner,
                                  RequestTransport transport, ExecutionOptions options,
                                  EvidenceWriter evidence, RunControl control) throws Exception {
        ScanOptions scanOptions = new ScanOptions(options.protocol(), options.requestTimeout(),
            options.globalConcurrency(), options.perHostConcurrency(), options.throttleStatusCodes(),
            options.retryAttempts(), !"idor".equals(mode), options.posture(), options.pauseMode(),
            options.fixedPauseMillis());
        var engine = new ScanEngine(scanOptions);
        var pending = new java.util.concurrent.ConcurrentHashMap<String, com.bypassfuzzer.core.input.RetryPackageEntry>();
        ScanEngine.Summary summary;
        try (var binding = control.bind(engine::pause, engine::resume, engine::stop)) {
        summary = engine.run(mode, inputs, planner,
            postBaselinePlanner, transport, event -> {
            try {
                evidence.write(event.mode(), event.target(), event.planned(), event.response(),
                    event.error(), event.signal(), event.retryAttempt());
                if (!event.planned().baseline()) {
                    String key = event.planned().family() + "\n" + event.planned().payload() + "\n" + event.planned().request().toRaw();
                    if (event.response() == null || options.throttleStatusCodes().contains(event.response().statusCode()))
                        pending.put(key, evidence.retryEntry(event.planned(), event.retryAttempt()));
                    else pending.remove(key);
                }
            } catch (java.io.IOException error) {
                throw new UncheckedIOException(error);
            }
        });
        }
        evidence.retryPackage(List.copyOf(pending.values()));
        var metadata = summary.asMap();
        metadata.put("deferredRetries", pending.size());
        metadata.put("requestsSent", summary.requestsSent());
        evidence.summary(metadata);
        System.err.printf("Completed %s: %d evidence records, %d findings, %d transport errors. Evidence: %s%n",
            mode, summary.records(), summary.findings(), summary.transportErrors(), evidence.root());
        return summary;
    }
}
