package com.bypassfuzzer.cli.run;

import com.bypassfuzzer.cli.evidence.EvidenceWriter;
import com.bypassfuzzer.core.http.HttpProtocol;
import com.bypassfuzzer.core.http.HttpRequestData;
import com.bypassfuzzer.core.http.HttpResponseData;
import com.bypassfuzzer.core.http.RequestTransport;
import com.bypassfuzzer.core.scan.PlannedRequest;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

public final class ScanExecutor {
    public RunSummary run(String mode, List<HttpRequestData> inputs,
                          Function<HttpRequestData, List<PlannedRequest>> planner,
                          RequestTransport transport, ExecutionOptions options,
                          EvidenceWriter evidence) throws Exception {
        Instant started = Instant.now();
        Map<String, Semaphore> hostPermits = new ConcurrentHashMap<>();
        AtomicInteger findings = new AtomicInteger();
        AtomicInteger transportErrors = new AtomicInteger();
        AtomicInteger throttled = new AtomicInteger();
        PauseGate pauseGate = new PauseGate(options);
        List<Task> tasks = new ArrayList<>();

        for (HttpRequestData input : inputs) {
            for (HttpProtocol protocol : protocols(options.protocol())) {
                HttpRequestData base = input.withProtocol(protocol);
                List<PlannedRequest> planned = new ArrayList<>(planner.apply(base));
                if (planned.stream().noneMatch(PlannedRequest::baseline)) {
                    planned.add(0, PlannedRequest.baseline(base, "Original request"));
                }
                HttpResponseData baseline = null;
                for (PlannedRequest item : planned) {
                    if (!item.baseline()) continue;
                    SendOutcome outcome = send(transport, item, options, hostPermits, pauseGate, 0);
                    evidence.write(mode, input.targetLabel(), item, outcome.response, outcome.error,
                        outcome.error == null ? "BASELINE" : "NO_RESPONSE", 0);
                    if (baseline == null && outcome.response != null) baseline = outcome.response;
                    if (outcome.error != null) transportErrors.incrementAndGet();
                }
                for (PlannedRequest item : planned) if (!item.baseline()) tasks.add(new Task(input.targetLabel(), item, baseline));
            }
        }

        ExecutorService pool = Executors.newFixedThreadPool(options.globalConcurrency());
        List<Future<?>> futures = new ArrayList<>();
        for (Task task : tasks) {
            futures.add(pool.submit(() -> {
                SendOutcome outcome = send(transport, task.planned, options, hostPermits, pauseGate, 0);
                String signal = classify(task.baseline, outcome.response, outcome.error, options);
                if ("LIKELY_BYPASS".equals(signal)) findings.incrementAndGet();
                if ("THROTTLED".equals(signal)) throttled.incrementAndGet();
                if (outcome.error != null) transportErrors.incrementAndGet();
                try { evidence.write(mode, task.target, task.planned, outcome.response, outcome.error, signal, 0); }
                catch (Exception exception) { throw new RuntimeException(exception); }
                if ((outcome.error != null || "THROTTLED".equals(signal)) && options.retryAttempts() > 0) {
                    for (int attempt = 1; attempt <= options.retryAttempts(); attempt++) {
                        SendOutcome retry = send(transport, task.planned, options, hostPermits, pauseGate, attempt);
                        String retrySignal = classify(task.baseline, retry.response, retry.error, options);
                        try { evidence.write(mode, task.target, task.planned, retry.response, retry.error, retrySignal, attempt); }
                        catch (Exception exception) { throw new RuntimeException(exception); }
                        if (retry.error == null && !"THROTTLED".equals(retrySignal)) break;
                    }
                }
            }));
        }
        pool.shutdown();
        for (Future<?> future : futures) future.get();

        RunSummary summary = new RunSummary("completed", mode, started.toString(), Instant.now().toString(),
            inputs.size(), evidence.count(), findings.get(), throttled.get(), transportErrors.get());
        evidence.summary(summary.asMap());
        System.err.printf("Completed %s: %d evidence records, %d likely bypasses, %d transport errors. Evidence: %s%n",
            mode, summary.records, summary.findings, summary.transportErrors, evidence.root());
        return summary;
    }

    private SendOutcome send(RequestTransport transport, PlannedRequest planned, ExecutionOptions options,
                             Map<String, Semaphore> hostPermits, PauseGate pauseGate, int attempt) {
        Semaphore semaphore = hostPermits.computeIfAbsent(planned.request().origin().authority(), ignored -> new Semaphore(options.perHostConcurrency()));
        boolean acquired = false;
        try {
            semaphore.acquire();
            acquired = true;
            pauseGate.await();
            if (attempt > 0) Thread.sleep(Math.min(5_000L, 500L * (1L << Math.min(attempt, 3))));
            HttpResponseData response = transport.send(planned.request(), options.requestTimeout());
            pauseGate.observe(response);
            return new SendOutcome(response, null);
        } catch (Throwable error) {
            return new SendOutcome(null, error);
        } finally {
            if (acquired) semaphore.release();
        }
    }

    private String classify(HttpResponseData baseline, HttpResponseData response, Throwable error, ExecutionOptions options) {
        if (error != null || response == null) return "NO_RESPONSE";
        if (options.throttleStatusCodes().contains(response.statusCode())) return "THROTTLED";
        if (baseline == null) return "UNCLASSIFIED";
        boolean blocked = baseline.statusCode() == 401 || baseline.statusCode() == 403;
        boolean success = response.statusCode() >= 200 && response.statusCode() < 400;
        if (blocked && success) return "LIKELY_BYPASS";
        if (baseline.statusCode() != response.statusCode() || Math.abs(baseline.body().length - response.body().length) >= 100) return "RESPONSE_CHANGED";
        return "NO_SIGNAL";
    }

    private List<HttpProtocol> protocols(HttpProtocol protocol) {
        return protocol == HttpProtocol.BOTH ? List.of(HttpProtocol.HTTP_1, HttpProtocol.HTTP_2) : List.of(protocol);
    }

    private record Task(String target, PlannedRequest planned, HttpResponseData baseline) {}
    private record SendOutcome(HttpResponseData response, Throwable error) {}

    private static final class PauseGate {
        private final ExecutionOptions options;
        private long resumeAt;
        private int recentThrottles;
        private long throttleWindowStarted;

        private PauseGate(ExecutionOptions options) { this.options = options; }

        synchronized void await() throws InterruptedException {
            long remaining;
            while ((remaining = resumeAt - System.currentTimeMillis()) > 0) wait(Math.min(remaining, 1_000L));
        }

        synchronized void observe(HttpResponseData response) {
            if (response == null || !options.throttleStatusCodes().contains(response.statusCode()) || options.pauseMode().equals("off")) return;
            long now = System.currentTimeMillis();
            if (now - throttleWindowStarted > 10_000L) { throttleWindowStarted = now; recentThrottles = 0; }
            recentThrottles++;
            boolean pause = options.pauseMode().equals("fixed") || recentThrottles >= (options.posture().equals("conservative") ? 2 : 3);
            if (pause) resumeAt = Math.max(resumeAt, now + options.fixedPauseMillis());
        }
    }

    public record RunSummary(String state, String mode, String startedAt, String finishedAt, int inputs,
                             long records, int findings, int throttled, int transportErrors) {
        public Map<String, Object> asMap() {
            Map<String, Object> values = new LinkedHashMap<>();
            values.put("schemaVersion", 1); values.put("state", state); values.put("mode", mode);
            values.put("startedAt", startedAt); values.put("finishedAt", finishedAt); values.put("inputs", inputs);
            values.put("records", records); values.put("findings", findings); values.put("throttled", throttled);
            values.put("transportErrors", transportErrors); return values;
        }
    }
}
