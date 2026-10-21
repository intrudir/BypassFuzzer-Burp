package com.bypassfuzzer.cli.run;
import com.bypassfuzzer.core.throttle.ThrottleSettings;

import com.bypassfuzzer.cli.evidence.EvidenceWriter;
import com.bypassfuzzer.core.http.*;
import com.bypassfuzzer.core.scan.*;
import com.bypassfuzzer.core.throttle.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.Function;

/** CLI transport/evidence adapter for the same Sweep workflow and retries used by Burp. */
public final class SweepExecutor {
    private record Retry(SweepWorkflow.Result<HttpRequestData, HttpResponseData> result, int attempt) { }

    public void run(List<HttpRequestData> inputs, Function<HttpRequestData, List<PlannedRequest>> planner,
        RequestTransport transport, ExecutionOptions execution, SweepWorkflow.Options options,
        RequestHeaderPolicy<HttpRequestData> policy, EvidenceWriter evidence, RunControl control) throws Exception {
        Instant started = Instant.now();
        var settings = new ThrottleSettings(execution.throttleStatusCodes(), execution.globalConcurrency(),
            execution.perHostConcurrency(), 400, ThrottleSettings.Posture.valueOf(execution.posture().replace('-', '_').toUpperCase()),
            ThrottleSettings.PauseMode.valueOf(execution.pauseMode().toUpperCase()), execution.fixedPauseMillis());
        var throttle = new HostThrottleCoordinator<HttpRequestData, HttpResponseData>(settings,
            r -> r.origin().toString(), HttpResponseData::statusCode, r -> r.firstHeader("Retry-After").orElse(null), System.err::println);
        var workflow = new SweepWorkflow<HttpRequestData, HttpResponseData>(RequestAccess.CORE, SweepClassifier::response);
        inputs = CandidateScheduler.interleave(inputs, r -> r.origin().host());
        var queue = new ConcurrentLinkedQueue<Retry>();
        var remainingByHost = new ConcurrentHashMap<String, AtomicInteger>();
        var completedHosts = ConcurrentHashMap.<String>newKeySet();
        int protocolCount = execution.protocol() == HttpProtocol.BOTH ? 2 : 1;
        for (var input : inputs) remainingByHost.computeIfAbsent(input.origin().host(), ignored -> new AtomicInteger()).addAndGet(protocolCount);
        var errors = new AtomicInteger();
        var findings = new AtomicInteger();
        var sent = new AtomicLong();
        var planned = new AtomicLong();
        var completed = new AtomicLong();
        var publicSkipped = new AtomicInteger();
        var quarantined = new AtomicInteger();
        Function<SweepWorkflow.Probe<HttpRequestData>, HttpResponseData> send = probe -> throttle.send(probe.request(), () -> {
            sent.incrementAndGet();
            try { return transport.send(probe.request(), execution.requestTimeout()); }
            catch (Exception error) { errors.incrementAndGet(); return null; }
        });
        java.util.function.Consumer<SweepWorkflow.Result<HttpRequestData, HttpResponseData>> emit = result -> {
            try {
                boolean baseline = result.probe().family().equals("Control") || result.probe().family().equals("Unauthenticated Control");
                evidence.write("sweep", result.target(), new PlannedRequest(result.probe().family(), result.probe().label(), "",
                    result.probe().request(), baseline), result.response(), null, result.signal(), 0);
                if (result.signal().startsWith(SweepClassifier.BYPASS_PREFIX)
                    || result.signal().startsWith(SweepClassifier.LIKELY_UNAUTHENTICATED_BYPASS_PREFIX)) findings.incrementAndGet();
                if (!result.probe().family().equals("Unauthenticated Control") && retryable(result.response(), execution)) queue.add(new Retry(result, 0));
            } catch (java.io.IOException error) { throw new java.io.UncheckedIOException(error); }
        };
        ExecutorService pool = Executors.newFixedThreadPool(execution.globalConcurrency());
        var tasks = new CopyOnWriteArrayList<Future<?>>();
        try (var binding = control.bind(throttle::manualPause, throttle::manualResume,
            () -> { throttle.manualResume(); tasks.forEach(task -> task.cancel(true)); pool.shutdownNow(); })) {
            for (HttpRequestData original : inputs) {
                if (!control.continuing()) break;
                List<HttpProtocol> protocols = execution.protocol() == HttpProtocol.BOTH
                    ? List.of(HttpProtocol.HTTP_1, HttpProtocol.HTTP_2) : List.of(execution.protocol());
                for (HttpProtocol protocol : protocols) tasks.add(pool.submit(() -> {
                    if (!control.continuing()) return;
                    var base = original.withProtocol(protocol);
                    HttpResponseData captured = null;
                    if (options.authenticated()) {
                        var capture = policy.reconcileMutation(base, base);
                        captured = send.apply(new SweepWorkflow.Probe<>("Authenticated captured control", "Control", capture, protocol));
                        try { evidence.write("sweep", base.targetLabel(), PlannedRequest.baseline(capture,
                            "Authenticated captured control"), captured, null, "BASELINE", 0); }
                        catch (java.io.IOException error) { throw new java.io.UncheckedIOException(error); }
                    }
                    var baseline = new SweepClassifier.Baseline(captured == null ? 0 : captured.statusCode(),
                        captured == null ? 0 : captured.body().length,
                        captured == null ? "" : captured.firstHeader("Content-Type").orElse(""));
                    var candidate = new SweepWorkflow.Candidate<>(base, captured, base.targetLabel(), baseline);
                    workflow.execute(candidate, options, policy, () -> {
                        var input = options.authenticated() ? workflow.stripAuthentication(base, options.authHeaders(), options.authCookies()) : base;
                        return planner.apply(input).stream().map(p -> new SweepWorkflow.Probe<>(p.payload(), p.family(), p.request(),
                            p.baseline() ? HttpProtocol.AUTO : p.request().protocol())).toList();
                    }, send, control::continuing, new SweepWorkflow.Observer<HttpRequestData, HttpResponseData>() {
                        public void planned(int count) { planned.addAndGet(count); }
                        public void completed() { completed.incrementAndGet(); }
                        public void skippedPublic() { publicSkipped.incrementAndGet(); }
                        public void result(SweepWorkflow.Result<HttpRequestData, HttpResponseData> r) { emit.accept(r); }
                    });
                    if (control.continuing() && remainingByHost.get(base.origin().host()).decrementAndGet() == 0)
                        completedHosts.add(base.origin().host());
                }));
            }
            for (var task : tasks) {
                try { task.get(); }
                catch (java.util.concurrent.CancellationException | java.util.concurrent.ExecutionException error) {
                    if (!control.stopped()) throw error;
                }
            }
        new DeferredRetryRunner<Retry>().run(queue, execution.retryAttempts(), execution.globalConcurrency(),
            control::continuing, retry -> retry.result().probe().request().origin().toString(),
            retry -> retry.result().probe().family(), retry -> {
                var r = retry.result();
                var request = r.originalRequest() == null ? r.probe().request() : r.originalRequest();
                var response = send.apply(new SweepWorkflow.Probe<>("Retry control canary", "Control", request, request.protocol()));
                return response != null && !execution.throttleStatusCodes().contains(response.statusCode());
            }, (retry, attempt) -> {
                var r = retry.result();
                var response = send.apply(r.probe());
                try { evidence.write("sweep", r.target(), new PlannedRequest(r.probe().family(), r.probe().label(), "",
                    r.probe().request(), false), response, null, r.signal(), attempt); }
                catch (java.io.IOException error) { throw new java.io.UncheckedIOException(error); }
                boolean again = retryable(response, execution);
                if (again) queue.add(new Retry(r, attempt));
                return again;
            }, quarantined::addAndGet, System.err::println);
        evidence.retryPackage(queue.stream().map(r -> evidence.retryEntry(new PlannedRequest(r.result().probe().family(),
            r.result().probe().label(), "", r.result().probe().request(), false), r.attempt())).toList());
        var summary = new LinkedHashMap<String, Object>();
        summary.put("schemaVersion", 1); summary.put("state", control.stopped() ? "stopped" : "completed"); summary.put("mode", "sweep");
        summary.put("startedAt", started.toString()); summary.put("finishedAt", Instant.now().toString());
        summary.put("inputs", inputs.size()); summary.put("records", evidence.count()); summary.put("requestsSent", sent.get());
        summary.put("findings", findings.get()); summary.put("transportErrors", errors.get());
        summary.put("plannedRequests", planned.get()); summary.put("completedRequests", completed.get());
        summary.put("skippedPublicEndpoints", publicSkipped.get()); summary.put("deferredRetries", queue.size());
        summary.put("quarantinedRetries", quarantined.get());
        summary.put("completedHosts", completedHosts.stream().sorted().toList());
        evidence.summary(summary);
        } finally { pool.shutdownNow(); }
    }
    private boolean retryable(HttpResponseData response, ExecutionOptions options) {
        return response == null || options.throttleStatusCodes().contains(response.statusCode());
    }
}
