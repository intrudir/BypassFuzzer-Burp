package com.bypassfuzzer.core.scan;
import com.bypassfuzzer.core.throttle.ThrottleSettings;

import com.bypassfuzzer.core.http.HttpProtocol;
import com.bypassfuzzer.core.http.HttpRequestData;
import com.bypassfuzzer.core.http.HttpResponseData;
import com.bypassfuzzer.core.http.RequestTransport;
import com.bypassfuzzer.core.http.RequestAccess;

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
    private final Object pauseGate = new Object();
    private com.bypassfuzzer.core.throttle.HostThrottleCoordinator<HttpRequestData, HttpResponseData> throttle;
    private final LiveRun live;
    private final boolean ownThrottle;
    private final RunLedger<Outcome> attempts = new RunLedger<>();
    private final Set<String> finished = ConcurrentHashMap.newKeySet();
    private final Set<String> published = ConcurrentHashMap.newKeySet();
    private volatile long generation;
    private volatile long headerGeneration;
    private com.bypassfuzzer.core.http.ResponseArchive archive;
    private final ThreadLocal<String> eventSeed=new ThreadLocal<>();
    private final AtomicLong requestsSent = new AtomicLong();
    private volatile boolean stopped;
    private volatile boolean paused;

    public ScanEngine(ScanOptions options) {
        this(options, true);
    }

    /** Burp already supplies the same shared controller at its Montoya boundary. */
    public ScanEngine(ScanOptions options, boolean ownThrottle) {
        this(options, ownThrottle, null);
    }

    public ScanEngine(ScanOptions options, boolean ownThrottle, LiveRun live) {
        this.options = options;
        this.live = live;
        this.generation = live==null ? 0 : live.snapshot().revision();
        this.ownThrottle = ownThrottle;
        this.globalPermits = new Semaphore(options.globalConcurrency());
        var settings = new com.bypassfuzzer.core.throttle.ThrottleSettings(options.throttleStatusCodes(),
            options.globalConcurrency(), options.perHostConcurrency(), 400,
            com.bypassfuzzer.core.throttle.ThrottleSettings.Posture.valueOf(options.posture().replace('-', '_').toUpperCase()),
            com.bypassfuzzer.core.throttle.ThrottleSettings.PauseMode.valueOf(options.pauseMode().toUpperCase()),
            options.fixedPauseMillis());
        throttle = ownThrottle ? new com.bypassfuzzer.core.throttle.HostThrottleCoordinator<>(settings,
            request -> request.origin().scheme() + "://" + request.origin().host().toLowerCase() + ":" + request.origin().port(),
            HttpResponseData::statusCode, response -> response.firstHeader("Retry-After").orElse(null), message -> {}) : null;
    }

    public long configurationRevision(){return generation;}
    public long headerRevision(){return headerGeneration;}
    public Set<Integer> throttleStatusCodes(){return options.throttleStatusCodes();}
    public LiveRun liveRun() { return live; }
    public void pause() { if (live != null) { live.pause(); return; } paused = true; if (throttle != null) throttle.manualPause(); }
    public void resume() { if (live != null) { live.resume(); return; } paused = false; if (throttle != null) throttle.manualResume(); synchronized (pauseGate) { pauseGate.notifyAll(); } }
    public void stop() { stopped = true; if (live != null) live.stop(); else resume(); }
    public boolean isPaused() { return live == null ? paused : live.snapshot().state() == LiveRun.State.PAUSED || live.snapshot().state() == LiveRun.State.PAUSING; }
    public long requestsSent() { return live==null ? requestsSent.get() : live.snapshot().requestsSent(); }

    public Summary run(String mode, List<HttpRequestData> inputs,
                       Function<HttpRequestData, List<PlannedRequest>> planner,
                       RequestTransport transport, Consumer<ScanEvent> events) throws Exception {
        return run(mode, inputs, planner, null, transport, events);
    }

    public Summary run(String mode, List<HttpRequestData> inputs,
                       Function<HttpRequestData, List<PlannedRequest>> planner,
                       PostBaselinePlanner postBaselinePlanner,
                       RequestTransport transport, Consumer<ScanEvent> events) throws Exception {
        attempts.clear();published.clear();finished.clear();
        try(var retained=new com.bypassfuzzer.core.http.ResponseArchive()) {
        archive=retained;
        Instant started = Instant.now();
        AtomicInteger records = new AtomicInteger();
        AtomicInteger findings = new AtomicInteger();
        AtomicInteger throttled = new AtomicInteger();
        AtomicInteger errors = new AtomicInteger();
        while (!stopped) {
        var generationSnapshot=live==null ? null : live.snapshot();
        generation=generationSnapshot==null ? 0 : generationSnapshot.revision();
        headerGeneration=generationSnapshot==null ? 0 : generationSnapshot.headerRevision();
        int concurrency = live == null ? options.globalConcurrency() : live.snapshot().configuration().concurrency();
        if (live != null && ownThrottle) {
            var old = new com.bypassfuzzer.core.throttle.ThrottleSettings(options.throttleStatusCodes(), concurrency,
                live.snapshot().configuration().perHostConcurrency(), live.snapshot().configuration().requestsPerSecond(),
                com.bypassfuzzer.core.throttle.ThrottleSettings.Posture.valueOf(options.posture().replace('-','_').toUpperCase()),
                com.bypassfuzzer.core.throttle.ThrottleSettings.PauseMode.valueOf(options.pauseMode().toUpperCase()), options.fixedPauseMillis());
            throttle = new com.bypassfuzzer.core.throttle.HostThrottleCoordinator<>(old, r -> r.origin().toString(),
                HttpResponseData::statusCode, r -> r.firstHeader("Retry-After").orElse(null), message -> {});
        }
        ExecutorService pool = Executors.newFixedThreadPool(concurrency);
        try {
            for(int inputIndex=0;inputIndex<inputs.size();inputIndex++) {
                HttpRequestData input=inputs.get(inputIndex);
                String seedKey=inputIndex+"\n"+input.targetLabel();
                if (stopped) break;
                if (live != null) { live.checkpoint(generation); if (!live.allowed(input.origin().host(),seedKey)) continue; }
                for (HttpProtocol protocol : protocols(options.protocol())) {
                    if (stopped) break;
                    HttpRequestData base = input.withProtocol(protocol);
                    if (live != null) base = live.snapshot().configuration().prepare(base, RequestAccess.CORE);
                    final HttpRequestData planningBase = base;
                    if(live!=null)live.planningSeed(seedKey+"\n"+protocol);
                    List<PlannedRequest> plan = new ArrayList<>(planner.apply(base));
                    if (live != null) plan.replaceAll(p -> p.withRequest(live.snapshot().configuration().policy(RequestAccess.CORE).reconcileMutation(planningBase,p.request())));
                    if (options.implicitBaseline() && plan.stream().noneMatch(PlannedRequest::baseline))
                        plan.add(0, PlannedRequest.baseline(base, "Original request"));
                    HttpResponseData authorized = null;
                    HttpResponseData target = null;
                    for (PlannedRequest item : plan) {
                        if (!item.baseline() || stopped) continue;
                        Outcome outcome = send(transport,item,0,seedKey);
                        if (stopped && outcome.response == null) break;
                        boolean idor = "idor".equals(mode);
                        boolean targetControl = idor && item.payload().equals("idor.baseline.target");
                        String signal = outcome.error != null || outcome.response == null ? "NO_RESPONSE" : "BASELINE";
                        if (idor && outcome.response != null) {
                            int status = outcome.response.statusCode();
                            if (targetControl && status >= 200 && status < 300) signal = "TARGET_BASELINE_2XX_REVIEW";
                            else if (targetControl && status == 500) signal = "TARGET_BASELINE_500_REVIEW";
                            else if (!targetControl && (status < 200 || status >= 300)) signal = "CONTROL_FAILED";
                            else if (targetControl && !isComparableIdorTargetStatus(status)) signal = "TARGET_BASELINE_INCONCLUSIVE";
                        }
                        publish(events, new ScanEvent(mode, input.targetLabel(), item, outcome.response, outcome.error, signal, 0), records, findings, throttled, errors);
                        if (item.controlRole() == ControlRole.TARGET) target = outcome.response;
                        else if ((item.controlRole() == ControlRole.ORIGINAL || item.controlRole() == ControlRole.AUTHORIZED) && authorized == null) authorized = outcome.response;
                    }
                    boolean idor = "idor".equals(mode);
                    boolean authorizedValid = authorized != null && authorized.statusCode() >= 200
                        && authorized.statusCode() < 300;
                    boolean targetComparable = target != null && isComparableIdorTargetStatus(target.statusCode());
                    if (idor && !authorizedValid) continue;
                    if (postBaselinePlanner != null) {
                        List<PlannedRequest> afterBaselines = postBaselinePlanner.plan(planningBase, authorized, target);
                        plan = new ArrayList<>(afterBaselines);
                    }
                    if (idor && !targetComparable && postBaselinePlanner == null) continue;
                    final Map<HttpProtocol,PlannedRequest> wildcardControls = new java.util.EnumMap<>(HttpProtocol.class);
                    final Map<HttpProtocol,HttpResponseData> wildcardResponses = new java.util.EnumMap<>(HttpProtocol.class);
                    if (options.wildcardCalibration() && (mode.equals("bypass") || mode.equals("sweep"))
                        && WildcardCalibration.eligible(base.method()) && !stopped) {
                        HttpRequestData seed = plan.stream().filter(p -> p.controlRole() == ControlRole.ORIGINAL)
                            .map(PlannedRequest::request).findFirst().orElse(base);
                        var controlProtocols = new java.util.LinkedHashSet<HttpProtocol>();
                        plan.stream().filter(p -> !p.baseline()).forEach(p -> controlProtocols.add(p.request().protocol()));
                        for (var controlProtocol : controlProtocols) {
                            if (stopped) break;
                            PlannedRequest fallback = new PlannedRequest("Calibration", WildcardCalibration.controlLabel(controlProtocol), "",
                                WildcardCalibration.control(seed.withProtocol(controlProtocol), RequestAccess.CORE),
                                true, ProbeIntent.STANDARD, "", "", "", ControlRole.WILDCARD);
                            if (live != null) {
                                final PlannedRequest generated = fallback;
                                fallback = live.control(seedKey+"\n"+controlProtocol,headerGeneration,() -> generated);
                            }
                            wildcardControls.put(controlProtocol, fallback);
                            Outcome calibration = send(transport,fallback,0,seedKey);
                            for (int attempt = 0;; attempt++) {
                                String controlSignal = calibration.error != null || calibration.response == null ? "CALIBRATION_UNAVAILABLE" :
                                    options.throttleStatusCodes().contains(calibration.response.statusCode()) ? "THROTTLED" : "CALIBRATION_CONTROL";
                                publish(events, new ScanEvent(mode, input.targetLabel(), fallback, calibration.response, calibration.error, controlSignal, attempt), records, findings, throttled, errors);
                                if (attempt >= options.retryAttempts() || stopped || !(calibration.response == null || "THROTTLED".equals(controlSignal))) break;
                                calibration = send(transport,fallback,attempt+1,seedKey);
                            }
                            if (calibration.response != null) wildcardResponses.put(controlProtocol, calibration.response);
                        }
                    }
                    final HttpResponseData authorizedBaseline = authorized;
                    final HttpResponseData targetBaseline = target;
                    List<Future<?>> pending = new ArrayList<>();
                    for (PlannedRequest item : plan) {
                        if (stopped) break;
                        if (item.baseline()) continue;
                        if(live!=null && !live.selected(item))continue;
                        String workKey = RunLedger.key(seedKey,item,0,0);
                        if (live != null && finished.contains(workKey)) continue;
                        if (idor && !targetComparable && item.intent() != ProbeIntent.MASS_ASSIGNMENT) continue;
                        pending.add(pool.submit(() -> {
                            Outcome outcome = send(transport,item,0,seedKey);
                            if (stopped && outcome.response == null) return;
                            String signal = classify(mode, item, authorizedBaseline, targetBaseline, outcome);
                            publish(events, new ScanEvent(mode, input.targetLabel(), item, outcome.response, outcome.error, signal, 0,
                                !wildcardControls.containsKey(item.request().protocol()) ? WildcardCalibration.Assessment.DISABLED : WildcardCalibration.compare(item.request().method(),
                                    SweepClassifier.response(wildcardResponses.get(item.request().protocol())), SweepClassifier.response(outcome.response), options.throttleStatusCodes()),
                                wildcardControls.get(item.request().protocol()), wildcardResponses.get(item.request().protocol())), records, findings, throttled, errors);
                            if (retryable(item.request().method()) && options.retryAttempts() > 0) {
                                for (int attempt = 1; attempt <= options.retryAttempts() && !stopped
                                    && (outcome.error != null || "THROTTLED".equals(signal)); attempt++) {
                                    outcome = send(transport,item,attempt,seedKey);
                                    signal = classify(mode, item, authorizedBaseline, targetBaseline, outcome);
                                    publish(events, new ScanEvent(mode, input.targetLabel(), item, outcome.response, outcome.error, signal, attempt,
                                !wildcardControls.containsKey(item.request().protocol()) ? WildcardCalibration.Assessment.DISABLED : WildcardCalibration.compare(item.request().method(),
                                    SweepClassifier.response(wildcardResponses.get(item.request().protocol())), SweepClassifier.response(outcome.response), options.throttleStatusCodes()),
                                wildcardControls.get(item.request().protocol()), wildcardResponses.get(item.request().protocol())), records, findings, throttled, errors);
                                }
                            }
                            if (live != null) { finished.add(workKey); attempts.removeWork(seedKey,item); }
                        }));
                        if (pending.size() >= concurrency * 2) awaitFirst(pending);
                    }
                    while (!pending.isEmpty()) awaitFirst(pending);
                }
            }
        } catch (LiveRun.Reconfigured changed) {
            // Workers waiting at the final gate unwind; the next generation replans all seeds.
        } catch (java.util.concurrent.CancellationException cancelled) {
            if (!stopped && (live == null || live.snapshot().state()!=LiveRun.State.STOPPED)) throw cancelled;
        } finally {
            pool.shutdownNow();
            while (!pool.awaitTermination(100, java.util.concurrent.TimeUnit.MILLISECONDS)) { }
        }
        if (live == null || stopped || generation == live.snapshot().revision()) break;
        }
        return new Summary(stopped ? "stopped" : "completed", mode, started.toString(), Instant.now().toString(),
            inputs.size(),records.get(),findings.get(),throttled.get(),errors.get(),requestsSent());
        }finally{attempts.clear();archive=null;}
    }

    private void awaitFirst(List<Future<?>> pending) throws Exception {
        try { pending.remove(0).get(); }
        catch (java.util.concurrent.ExecutionException e) {
            if (e.getCause() instanceof LiveRun.Reconfigured changed) throw changed;
            if (e.getCause() instanceof java.util.concurrent.CancellationException cancelled) throw cancelled;
            throw e;
        }
    }

    private Outcome send(RequestTransport transport, PlannedRequest item, int attempt, String seed) {
        eventSeed.set(seed);
        String key = RunLedger.key(seed,item,live == null ? 0 : headerGeneration,attempt);
        java.util.function.Supplier<Outcome> action = () -> {
            ExchangeResult<HttpResponseData> result = exchange(item.request(), () -> {
                java.util.function.Supplier<HttpResponseData> physical = () -> {
                    try {
                        return transport.sendManaged(item.request(),options.requestTimeout(),live,generation);
                    } catch (LiveRun.Reconfigured | java.util.concurrent.CancellationException error) { throw error; }
                    catch (Exception error) { throw new java.util.concurrent.CompletionException(error); }
                };
                return throttle == null ? physical.get() : throttle.send(item.request(),physical,() -> {
                    if (live != null) live.checkpoint(generation);
                    return !stopped;
                });
            },HttpResponseData::statusCode,attempt);
            return new Outcome(live==null ? result.response() : archive.retain(result.response()),result.error());
        };
        return live == null ? action.get() : attempts.get(key,action).value();
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
            if (live != null) live.checkpoint(generation);
            else { globalPermits.acquire(); globalAcquired = true;
                host.acquire(); hostAcquired = true; }
            synchronized (pauseGate) {
                while (paused && !stopped) pauseGate.wait(250);
            }
            if (stopped) return new ExchangeResult<>(null, new InterruptedException("Scan stopped"));
            if (attempt > 0) Thread.sleep(Math.min(5_000L, 500L * (1L << Math.min(attempt, 3))));
            requestsSent.incrementAndGet();
            T response = action.send();
            return new ExchangeResult<>(response, null);
        } catch (LiveRun.Reconfigured | java.util.concurrent.CancellationException error) { throw error;
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

    public static boolean isComparableIdorTargetStatus(int status) {
        return (status >= 200 && status < 300) || isIdorDeniedTargetStatus(status);
    }

    private static boolean isIdorDeniedTargetStatus(int status) {
        // Some applications report permission failures as internal server errors.
        return status == 401 || status == 403 || status == 404 || status == 500;
    }

    private String classify(String mode,PlannedRequest item,HttpResponseData authorized,HttpResponseData target,Outcome outcome) {
        return classifyResponse(mode,item,authorized,target,outcome.response(),outcome.error(),options.throttleStatusCodes());
    }
    public static String classifyResponse(String mode,PlannedRequest item,HttpResponseData authorized,HttpResponseData target,
                                         HttpResponseData received,Throwable error,Set<Integer> throttleCodes) {
        if (error != null || received == null) return "NO_RESPONSE";
        HttpResponseData response = received;
        if (throttleCodes.contains(response.statusCode())) return "THROTTLED";
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
        if (mode.equals("sweep")) return SweepClassifier.signal(new SweepClassifier.Baseline(
            baseline.statusCode(), baseline.bodyLength(), baseline.firstHeader("Content-Type").orElse("")), SweepClassifier.response(baseline), SweepClassifier.response(response));
        boolean blocked = baseline.statusCode() == 401 || baseline.statusCode() == 403;
        boolean success = response.statusCode() >= 200 && response.statusCode() < 400;
        if ("idor".equals(mode) && isIdorDeniedTargetStatus(baseline.statusCode()) && success)
            return "IDOR_CANDIDATE";
        if ("idor".equals(mode) && baseline.statusCode() >= 200 && baseline.statusCode() < 300
            && !Arrays.equals(response.body(), baseline.body())) return "RESPONSE_CHANGED";
        if (blocked && success) return "LIKELY_BYPASS";
        if (baseline.statusCode() != response.statusCode()
            || Math.abs(baseline.bodyLength() - response.bodyLength()) >= 100) return "RESPONSE_CHANGED";
        return "NO_SIGNAL";
    }

    private void publish(Consumer<ScanEvent> events, ScanEvent event, AtomicInteger records,
                         AtomicInteger findings, AtomicInteger throttled, AtomicInteger errors) {
        if (live != null && !published.add(RunLedger.key(eventSeed.get(),event.planned(),headerGeneration,event.retryAttempt()))) return;
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
