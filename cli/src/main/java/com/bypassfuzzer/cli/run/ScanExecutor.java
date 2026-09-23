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
    public ScanEngine.Summary run(String mode, List<HttpRequestData> inputs,
                                  Function<HttpRequestData, List<PlannedRequest>> planner,
                                  RequestTransport transport, ExecutionOptions options,
                                  EvidenceWriter evidence) throws Exception {
        return run(mode, inputs, planner, null, transport, options, evidence);
    }

    public ScanEngine.Summary run(String mode, List<HttpRequestData> inputs,
                                  Function<HttpRequestData, List<PlannedRequest>> planner,
                                  ScanEngine.PostBaselinePlanner postBaselinePlanner,
                                  RequestTransport transport, ExecutionOptions options,
                                  EvidenceWriter evidence) throws Exception {
        ScanOptions scanOptions = new ScanOptions(options.protocol(), options.requestTimeout(),
            options.globalConcurrency(), options.perHostConcurrency(), options.throttleStatusCodes(),
            options.retryAttempts(), !"idor".equals(mode), options.posture(), options.pauseMode(),
            options.fixedPauseMillis());
        ScanEngine.Summary summary = new ScanEngine(scanOptions).run(mode, inputs, planner,
            postBaselinePlanner, transport, event -> {
            try {
                evidence.write(event.mode(), event.target(), event.planned(), event.response(),
                    event.error(), event.signal(), event.retryAttempt());
            } catch (java.io.IOException error) {
                throw new UncheckedIOException(error);
            }
        });
        evidence.summary(summary.asMap());
        System.err.printf("Completed %s: %d evidence records, %d findings, %d transport errors. Evidence: %s%n",
            mode, summary.records(), summary.findings(), summary.transportErrors(), evidence.root());
        return summary;
    }
}
