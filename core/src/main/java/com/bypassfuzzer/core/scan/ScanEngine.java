package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.HttpProtocol;
import com.bypassfuzzer.core.http.HttpRequestData;
import com.bypassfuzzer.core.http.HttpResponseData;
import com.bypassfuzzer.core.http.RequestTransport;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.ToIntFunction;

/** Executes every scan mode through the same admission, retry, and result path. */
public final class ScanEngine {
    private final ScanOptions options;
    private final Map<String, Semaphore> hostPermits = new ConcurrentHashMap<>();
    private final Semaphore globalPermits;
    private final PauseGate pauseGate;
    private final AtomicLong requestsSent = new AtomicLong();
    private volatile boolean stopped;
    private volatile boolean paused;

    public ScanEngine(ScanOptions options) {
        this.options = options;
        this.globalPermits = new Semaphore(options.globalConcurrency());
        this.pauseGate = new PauseGate(options);
    }

    public void pause() { paused = true; }
    public void resume() { paused = false; synchronized (pauseGate) { pauseGate.notifyAll(); } }
    public void stop() { stopped = true; resume(); }
    public boolean isPaused() { return paused; }
    public long requestsSent() { return requestsSent.get(); }

    public Summary run(String mode, List<HttpRequestData> inputs,
                       Function<HttpRequestData, List<PlannedRequest>> planner,
                       RequestTransport transport, Consumer<ScanEvent> events) throws Exception {
        return run(mode, inputs, planner, null, transport, events);
    }

    public Summary run(String mode, List<HttpRequestData> inputs,
                       Function<HttpRequestData, List<PlannedRequest>> planner,
                       PostBaselinePlanner postBaselinePlanner,
                       RequestTransport transport, Consumer<ScanEvent> events) throws Exception {
        Instant started = Instant.now();
        AtomicInteger records = new AtomicInteger();
        AtomicInteger findings = new AtomicInteger();
        AtomicInteger throttled = new AtomicInteger();
        AtomicInteger errors = new AtomicInteger();
        ExecutorService pool = Executors.newFixedThreadPool(options.globalConcurrency());
        try {
            for (HttpRequestData input : inputs) {
                if (stopped) break;
                for (HttpProtocol protocol : protocols(options.protocol())) {
                    if (stopped) break;
                    HttpRequestData base = input.withProtocol(protocol);
                    List<PlannedRequest> plan = new ArrayList<>(planner.apply(base));
                    if (options.implicitBaseline() && plan.stream().noneMatch(PlannedRequest::baseline))
                        plan.add(0, PlannedRequest.baseline(base, "Original request"));
                    HttpResponseData authorized = null;
                    HttpResponseData target = null;
                    for (PlannedRequest item : plan) {
                        if (!item.baseline() || stopped) continue;
                        Outcome outcome = send(transport, item, 0);
                        boolean idor = "idor".equals(mode);
                        boolean targetControl = idor && item.payload().equals("idor.baseline.target");
                        String signal = outcome.error != null || outcome.response == null ? "NO_RESPONSE" : "BASELINE";
                        if (idor && outcome.response != null) {
                            int status = outcome.response.statusCode();
                            if (targetControl && status >= 200 && status < 300) signal = "TARGET_BASELINE_2XX_REVIEW";
                            else if (!targetControl && (status < 200 || status >= 300)) signal = "CONTROL_FAILED";
                            else if (targetControl && status != 401 && status != 403 && status != 404) signal = "TARGET_BASELINE_INCONCLUSIVE";
                        }
                        publish(events, new ScanEvent(mode, input.targetLabel(), item, outcome.response, outcome.error, signal, 0), records, findings, throttled, errors);
                        if (targetControl) target = outcome.response;
                        else if (authorized == null) authorized = outcome.response;
                    }
                    boolean idor = "idor".equals(mode);
                    boolean authorizedValid = authorized != null && authorized.statusCode() >= 200
                        && authorized.statusCode() < 300;
                    boolean targetComparable = target != null && ((target.statusCode() >= 200
                        && target.statusCode() < 300) || target.statusCode() == 401
                        || target.statusCode() == 403 || target.statusCode() == 404);
                    if (idor && !authorizedValid) continue;
                    if (postBaselinePlanner != null) {
                        List<PlannedRequest> afterBaselines = postBaselinePlanner.plan(base, authorized, target);
                        plan = new ArrayList<>(afterBaselines);
                    }
                    if (idor && !targetComparable && postBaselinePlanner == null) continue;
                    final HttpResponseData authorizedBaseline = authorized;
                    final HttpResponseData targetBaseline = target;
                    List<Future<?>> pending = new ArrayList<>();
                    for (PlannedRequest item : plan) {
                        if (stopped) break;
                        if (item.baseline()) continue;
                        if (idor && !targetComparable && item.intent() != ProbeIntent.MASS_ASSIGNMENT) continue;
                        pending.add(pool.submit(() -> {
                            Outcome outcome = send(transport, item, 0);
                            String signal = classify(mode, item, authorizedBaseline, targetBaseline, outcome);
                            publish(events, new ScanEvent(mode, input.targetLabel(), item, outcome.response, outcome.error, signal, 0), records, findings, throttled, errors);
                            if (retryable(item.request().method()) && options.retryAttempts() > 0) {
                                for (int attempt = 1; attempt <= options.retryAttempts() && !stopped
                                    && (outcome.error != null || "THROTTLED".equals(signal)); attempt++) {
                                    outcome = send(transport, item, attempt);
                                    signal = classify(mode, item, authorizedBaseline, targetBaseline, outcome);
                                    publish(events, new ScanEvent(mode, input.targetLabel(), item, outcome.response, outcome.error, signal, attempt), records, findings, throttled, errors);
                                }
                            }
                        }));
                        if (pending.size() >= options.globalConcurrency() * 2) awaitFirst(pending);
                    }
                    while (!pending.isEmpty()) awaitFirst(pending);
                }
            }
        } finally {
            pool.shutdownNow();
        }
        return new Summary(stopped ? "stopped" : "completed", mode, started.toString(), Instant.now().toString(),
            inputs.size(), records.get(), findings.get(), throttled.get(), errors.get(), requestsSent.get());
    }

    private void awaitFirst(List<Future<?>> pending) throws Exception {
        pending.remove(0).get();
    }

    private Outcome send(RequestTransport transport, PlannedRequest item, int attempt) {
        ExchangeResult<HttpResponseData> result = exchange(item.request(),
            () -> transport.send(item.request(), options.requestTimeout()), HttpResponseData::statusCode, attempt);
        return new Outcome(result.response(), result.error());
    }

    /** Shared admission and pacing for adapters with a specialized scan workflow. */
    public <T> ExchangeResult<T> exchange(HttpRequestData request, CheckedExchange<T> action,
                                           ToIntFunction<T> statusCode) {
        return exchange(request, action, statusCode, 0);
    }

    private <T> ExchangeResult<T> exchange(HttpRequestData request, CheckedExchange<T> action,
                                            ToIntFunction<T> statusCode, int attempt) {
        Semaphore host = hostPermits.computeIfAbsent(request.origin().toString(),
            ignored -> new Semaphore(options.perHostConcurrency()));
        boolean globalAcquired = false, hostAcquired = false;
        try {
            globalPermits.acquire(); globalAcquired = true;
            host.acquire(); hostAcquired = true;
            synchronized (pauseGate) {
                while (paused && !stopped) pauseGate.wait(250);
                pauseGate.await(() -> stopped);
            }
            if (stopped) return new ExchangeResult<>(null, new InterruptedException("Scan stopped"));
            if (attempt > 0) Thread.sleep(Math.min(5_000L, 500L * (1L << Math.min(attempt, 3))));
            requestsSent.incrementAndGet();
            T response = action.send();
            if (response != null) pauseGate.observe(statusCode.applyAsInt(response));
            return new ExchangeResult<>(response, null);
        } catch (Exception error) {
            return new ExchangeResult<>(null, error);
        } finally {
            if (hostAcquired) host.release();
            if (globalAcquired) globalPermits.release();
        }
    }

    private boolean retryable(String method) {
        return options.retryStateChanging() || Set.of("GET", "HEAD", "OPTIONS").contains(method.toUpperCase());
    }

    private String classify(String mode, PlannedRequest item, HttpResponseData authorized,
                            HttpResponseData target, Outcome outcome) {
        if (outcome.error != null || outcome.response == null) return "NO_RESPONSE";
        HttpResponseData response = outcome.response;
        if (options.throttleStatusCodes().contains(response.statusCode())) return "THROTTLED";
        if (item.intent() == ProbeIntent.MASS_ASSIGNMENT) {
            if (response.statusCode() < 200 || response.statusCode() >= 300) return "REJECTED_OR_UNSUPPORTED";
            String observed = ResponseGuidedIdorPlanner.valueAt(response, item.sourcePointer());
            String before = ResponseGuidedIdorPlanner.valueAt(authorized, item.sourcePointer());
            return item.targetIdentifier().equals(observed) && !item.targetIdentifier().equals(before)
                ? "MASS_ASSIGNMENT_CANDIDATE" : "WRITE_INCONCLUSIVE";
        }
        if (item.intent() == ProbeIntent.PATH_BODY_CONFLICT) {
            if (response.statusCode() < 200 || response.statusCode() >= 300) return "NO_SIGNAL";
            String observed = ResponseGuidedIdorPlanner.valueAt(response, item.sourcePointer());
            return item.targetIdentifier().equals(observed)
                ? "IDOR_CANDIDATE" : "PATH_BODY_CONFLICT_INCONCLUSIVE";
        }
        HttpResponseData baseline = "idor".equals(mode) ? target : authorized;
        if (baseline == null) return "UNCLASSIFIED";
        boolean blocked = baseline.statusCode() == 401 || baseline.statusCode() == 403;
        boolean success = response.statusCode() >= 200 && response.statusCode() < 400;
        if ("idor".equals(mode) && (blocked || baseline.statusCode() == 404) && success)
            return "IDOR_CANDIDATE";
        if ("idor".equals(mode) && baseline.statusCode() >= 200 && baseline.statusCode() < 300
            && !Arrays.equals(response.body(), baseline.body())) return "RESPONSE_CHANGED";
        if (blocked && success) return "LIKELY_BYPASS";
        if (baseline.statusCode() != response.statusCode()
            || Math.abs(baseline.body().length - response.body().length) >= 100) return "RESPONSE_CHANGED";
        return "NO_SIGNAL";
    }

    private void publish(Consumer<ScanEvent> events, ScanEvent event, AtomicInteger records,
                         AtomicInteger findings, AtomicInteger throttled, AtomicInteger errors) {
        events.accept(event);
        records.incrementAndGet();
        if ("LIKELY_BYPASS".equals(event.signal()) || "IDOR_CANDIDATE".equals(event.signal())
            || "MASS_ASSIGNMENT_CANDIDATE".equals(event.signal())) findings.incrementAndGet();
        if ("THROTTLED".equals(event.signal())) throttled.incrementAndGet();
        if (event.error() != null) errors.incrementAndGet();
    }

    private List<HttpProtocol> protocols(HttpProtocol protocol) {
        return protocol == HttpProtocol.BOTH ? List.of(HttpProtocol.HTTP_1, HttpProtocol.HTTP_2) : List.of(protocol);
    }

    private record Outcome(HttpResponseData response, Throwable error) { }
    @FunctionalInterface public interface PostBaselinePlanner {
        List<PlannedRequest> plan(HttpRequestData request, HttpResponseData authorized,
                                  HttpResponseData target);
    }
    @FunctionalInterface public interface CheckedExchange<T> { T send() throws Exception; }
    public record ExchangeResult<T>(T response, Throwable error) { }

    private static final class PauseGate {
        private final ScanOptions options;
        private long resumeAt;
        private int recentThrottles;
        private long throttleWindowStarted;
        PauseGate(ScanOptions options) { this.options = options; }
        synchronized void await(java.util.function.BooleanSupplier stopped) throws InterruptedException {
            long remaining;
            while (!stopped.getAsBoolean() && (remaining = resumeAt - System.currentTimeMillis()) > 0)
                wait(Math.min(remaining, 250L));
        }
        synchronized void observe(int statusCode) {
            if (!options.throttleStatusCodes().contains(statusCode) || options.pauseMode().equals("off")) return;
            long now = System.currentTimeMillis();
            if (now - throttleWindowStarted > 10_000L) { throttleWindowStarted = now; recentThrottles = 0; }
            recentThrottles++;
            if (options.pauseMode().equals("fixed") || recentThrottles >= (options.posture().equals("conservative") ? 2 : 3))
                resumeAt = Math.max(resumeAt, now + options.fixedPauseMillis());
        }
    }

    public record Summary(String state, String mode, String startedAt, String finishedAt, int inputs,
                          long records, int findings, int throttled, int transportErrors, long requestsSent) {
        public Map<String, Object> asMap() {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("schemaVersion", 1); result.put("state", state); result.put("mode", mode);
            result.put("startedAt", startedAt); result.put("finishedAt", finishedAt); result.put("inputs", inputs);
            result.put("records", records); result.put("findings", findings); result.put("throttled", throttled);
            result.put("transportErrors", transportErrors);
            return result;
        }
    }
}
