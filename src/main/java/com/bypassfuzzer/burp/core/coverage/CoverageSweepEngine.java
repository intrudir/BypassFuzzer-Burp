package com.bypassfuzzer.burp.core.coverage;
import com.bypassfuzzer.core.scan.*;
import com.bypassfuzzer.core.input.PostmanCollectionParser;
import com.bypassfuzzer.core.input.OpenApiSpecParser;
import com.bypassfuzzer.core.input.OpenApiImportOptions;
import com.bypassfuzzer.core.input.OpenApiOperation;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.throttle.HostThrottleCoordinator;
import com.bypassfuzzer.burp.core.throttle.GlobalTrafficGovernor;
import com.bypassfuzzer.burp.core.ExecutionPauseController;
import com.bypassfuzzer.core.throttle.ThrottleSettings;
import com.bypassfuzzer.burp.http.MontoyaRequestSender;
import com.bypassfuzzer.core.http.RequestPathUtils;
import com.bypassfuzzer.burp.http.RequestHeaderUtils;
import com.bypassfuzzer.burp.http.RequestSender;
import com.bypassfuzzer.burp.http.TargetUrlResolver;
import com.bypassfuzzer.burp.http.ConfiguredHeaderPolicy;
import com.bypassfuzzer.core.http.CookieHeaderUtils;
import com.bypassfuzzer.burp.http.CoreRequestAdapter;
import com.bypassfuzzer.core.http.HttpProtocol;
import com.bypassfuzzer.core.scan.ScanEngine;
import com.bypassfuzzer.core.scan.ScanOptions;
import java.time.Duration;

import java.net.URI;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.regex.Pattern;

public class CoverageSweepEngine {

    private static final int MAX_AUTOMATIC_THROTTLE_RETRIES = 3;

    private final MontoyaApi api;
    private final RequestSender requestSender;
    private final CoverageSweepProbeGenerator probeGenerator;
    private final FullBypassSweepProbeGenerator fullProbeGenerator;
    private final ExecutionPauseController pauseController = new ExecutionPauseController();
    private volatile LiveRun live;
    private volatile long generation;
    private volatile long headerGeneration;
    private final java.util.Map<String,com.bypassfuzzer.core.scan.SweepWorkflow.Memory<HttpRequest,HttpResponse>> liveMemories=new java.util.concurrent.ConcurrentHashMap<>();
    private final com.bypassfuzzer.core.scan.RunLedger<java.util.Optional<HttpResponse>> refreshedCaptures=new com.bypassfuzzer.core.scan.RunLedger<>();
    private final UrlRequestFactory urlRequestFactory;
    private final TargetUrlResolver targetUrlResolver = new TargetUrlResolver();

    private volatile boolean running = false;
    private Thread runnerThread;
    private ExecutorService executor;
    private volatile HostThrottleCoordinator coordinator;
    private volatile ScanEngine coreScan;
    private final CoreRequestAdapter coreRequests = new CoreRequestAdapter();
    private volatile ConcurrentLinkedQueue<RetryTask> deferredRetryQueue = new ConcurrentLinkedQueue<>();
    private final Set<String> sweepHosts = ConcurrentHashMap.newKeySet();
    private final Set<String> completedSweepHosts = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<String, AtomicInteger> pendingHostCandidates = new ConcurrentHashMap<>();
    private final AtomicInteger plannedMainRequests = new AtomicInteger();
    private final AtomicInteger skippedPublicEndpoints = new AtomicInteger();
    private final AtomicInteger completedMainRequests = new AtomicInteger();
    private final AtomicInteger sentRequests = new AtomicInteger();
    private final AtomicInteger automaticRetryRequests = new AtomicInteger();
    private final AtomicInteger quarantinedRetryRequests = new AtomicInteger();
    private volatile SweepPhase phase = SweepPhase.IDLE;
    private final AtomicInteger failedCandidates = new AtomicInteger();
    private final java.util.concurrent.ArrayBlockingQueue<String> failures = new java.util.concurrent.ArrayBlockingQueue<>(100);
    private final Set<String> failedSweepHosts = ConcurrentHashMap.newKeySet();

    public enum SweepPhase {
        IDLE,
        PREPARING,
        MAIN_SWEEP,
        AUTOMATIC_RETRIES,
        COMPLETE,
        FAILED,
        STOPPED
    }

    public CoverageSweepEngine(MontoyaApi api) {
        this(api, new MontoyaRequestSender(api, true), new CoverageSweepProbeGenerator());
    }

    public CoverageSweepEngine(MontoyaApi api, GlobalTrafficGovernor globalGovernor) {
        this(api, new MontoyaRequestSender(api, globalGovernor, true), new CoverageSweepProbeGenerator());
    }

    CoverageSweepEngine(MontoyaApi api, RequestSender requestSender, CoverageSweepProbeGenerator probeGenerator) {
        this(api, requestSender, probeGenerator, CoverageSweepEngine::defaultImportedRequest);
    }

    CoverageSweepEngine(MontoyaApi api,
                        RequestSender requestSender,
                        CoverageSweepProbeGenerator probeGenerator,
                        UrlRequestFactory urlRequestFactory) {
        this.api = api;
        this.requestSender = requestSender;
        this.probeGenerator = probeGenerator;
        this.fullProbeGenerator = new FullBypassSweepProbeGenerator(api);
        this.urlRequestFactory = urlRequestFactory == null ? CoverageSweepEngine::defaultImportedRequest : urlRequestFactory;
    }

    public CoverageSweepPreview collectPreview(CoverageSweepOptions options) {
        return collectPreview(options, true);
    }

    public CoverageSweepPreview collectPreview(CoverageSweepOptions options,
                                                boolean dedupeOnEndpoint) {
        CoverageSweepOptions effectiveOptions = options == null ? CoverageSweepOptions.defaults() : options;
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        history = history == null ? List.of() : history;
        int successfulResponseCount = effectiveOptions.mode() == CoverageSweepMode.AUTHENTICATED_TRAFFIC
            ? (int) history.stream().filter(this::hasSuccessfulResponse).count()
            : 0;
        int inScopeSuccessfulResponseCount = effectiveOptions.mode() == CoverageSweepMode.AUTHENTICATED_TRAFFIC
            ? (int) history.stream().filter(this::hasSuccessfulResponse)
                .filter(item -> !effectiveOptions.inScopeOnly() || isInScope(item)).count()
            : 0;
        List<ProxyHttpRequestResponse> matchingHistory = history.stream()
            .filter(item -> eligible(item, effectiveOptions))
            .toList();
        Map<String, CoverageSweepCandidate> deduped = new LinkedHashMap<>();
        List<CoverageSweepCandidate> collected = new ArrayList<>();
        Set<String> discoveredHeaders = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        Set<String> discoveredCookies = new TreeSet<>();

        for (ProxyHttpRequestResponse item : matchingHistory) {
            CoverageSweepCandidate candidate = toCandidate(item);
            if (candidate == null) {
                continue;
            }

            collected.add(candidate);
            CoverageSweepCandidate existing = deduped.get(candidate.dedupeKey());
            if (existing == null || newer(candidate.time(), existing.time())) {
                deduped.put(candidate.dedupeKey(), candidate);
            }
            if (effectiveOptions.mode() == CoverageSweepMode.AUTHENTICATED_TRAFFIC) {
                collectAuthIdentifiers(candidate.request(), discoveredHeaders, discoveredCookies);
            }
        }

        List<CoverageSweepCandidate> candidates = dedupeOnEndpoint
            ? new ArrayList<>(deduped.values()) : collected;
        candidates.sort(Comparator
            .comparing(CoverageSweepCandidate::time, Comparator.nullsLast(Comparator.reverseOrder()))
            .thenComparing(CoverageSweepCandidate::displayUrl, Comparator.nullsLast(String::compareTo)));

        int cap = Math.max(1, effectiveOptions.maxCandidates());
        if (effectiveOptions.mode() == CoverageSweepMode.BLOCKED_RESPONSES && candidates.size() > cap) {
            candidates = new ArrayList<>(candidates.subList(0, cap));
        }

        return new CoverageSweepPreview(matchingHistory.size(), deduped.size(), List.copyOf(candidates),
            Set.copyOf(discoveredHeaders), Set.copyOf(discoveredCookies), history.size(),
            successfulResponseCount, inScopeSuccessfulResponseCount);
    }

    public CoverageSweepPreview collectPreviewFromUrls(List<String> urls, CoverageSweepOptions options) {
        return collectPreviewFromUrls(urls, options, true);
    }

    public CoverageSweepPreview collectPreviewFromUrls(List<String> urls, CoverageSweepOptions options,
                                                        boolean dedupeEndpoints) {
        if (urls == null || urls.isEmpty()) {
            return new CoverageSweepPreview(0, 0, List.of());
        }

        Map<String, CoverageSweepCandidate> deduped = new LinkedHashMap<>();
        List<CoverageSweepCandidate> imported = new ArrayList<>();
        int parsedTargets = 0;

        for (String url : urls) {
            CoverageSweepCandidate candidate = toImportedCandidate(url);
            if (candidate == null) {
                continue;
            }
            parsedTargets++;
            deduped.putIfAbsent(candidate.dedupeKey(), candidate);
            imported.add(candidate);
        }

        List<CoverageSweepCandidate> candidates = dedupeEndpoints
            ? new ArrayList<>(deduped.values()) : imported;
        candidates.sort(Comparator.comparing(CoverageSweepCandidate::displayUrl, Comparator.nullsLast(String::compareTo)));

        return new CoverageSweepPreview(parsedTargets, deduped.size(), List.copyOf(candidates));
    }

    public CoverageSweepPreview collectPreviewFromOpenApi(String source, String fileName,
                                                           CoverageSweepOptions options) {
        return collectPreviewFromOpenApi(source, fileName, "", options);
    }

    public CoverageSweepPreview collectPreviewFromOpenApi(String source, String fileName,
                                                           String baseUrlOverride,
                                                           CoverageSweepOptions options) {
        return collectPreviewFromOpenApi(source, fileName, baseUrlOverride, "", options);
    }

    public CoverageSweepPreview collectPreviewFromOpenApi(String source, String fileName,
                                                           String baseUrlOverride,
                                                           String sourceUrl,
                                                           CoverageSweepOptions options) {
        return collectPreviewFromOpenApi(source, fileName, baseUrlOverride, sourceUrl, options, true);
    }

    public CoverageSweepPreview collectPreviewFromOpenApi(String source, String fileName,
                                                           String baseUrlOverride,
                                                           String sourceUrl,
                                                           CoverageSweepOptions options,
                                                           boolean dedupeEndpoints) {
        return collectPreviewFromOpenApi(source, fileName, baseUrlOverride, sourceUrl,
            options, dedupeEndpoints, OpenApiImportOptions.DEFAULT);
    }

    public CoverageSweepPreview collectPreviewFromOpenApi(String source, String fileName,
                                                           String baseUrlOverride, String sourceUrl,
                                                           CoverageSweepOptions options,
                                                           boolean dedupeEndpoints,
                                                           OpenApiImportOptions importOptions) {
        List<OpenApiOperation> operations = new OpenApiSpecParser().parseTemplates(
            source, fileName, baseUrlOverride, sourceUrl, importOptions);
        Map<String, CoverageSweepCandidate> deduped = new LinkedHashMap<>();
        List<CoverageSweepCandidate> imported = new ArrayList<>();
        for (OpenApiOperation operation : operations) {
            CoverageSweepCandidate candidate = toImportedCandidate(operation);
            if (candidate != null) {
                deduped.putIfAbsent(candidate.dedupeKey(), candidate);
                imported.add(candidate);
            }
        }
        List<CoverageSweepCandidate> candidates = dedupeEndpoints
            ? new ArrayList<>(deduped.values()) : imported;
        candidates.sort(Comparator.comparing(CoverageSweepCandidate::displayUrl, Comparator.nullsLast(String::compareTo))
            .thenComparing(CoverageSweepCandidate::method));
        return new CoverageSweepPreview(operations.size(), deduped.size(), List.copyOf(candidates));
    }

    public CoverageSweepPreview collectPreviewFromPostman(String source, String baseUrlOverride,
                                                           CoverageSweepOptions options,
                                                           boolean dedupeEndpoints) {
        List<OpenApiOperation> operations = new PostmanCollectionParser().parse(source, baseUrlOverride);
        Map<String, CoverageSweepCandidate> deduped = new LinkedHashMap<>();
        List<CoverageSweepCandidate> imported = new ArrayList<>();
        for (OpenApiOperation operation : operations) {
            CoverageSweepCandidate candidate = toImportedCandidate(operation);
            if (candidate != null) {
                deduped.putIfAbsent(candidate.dedupeKey(), candidate);
                imported.add(candidate);
            }
        }
        List<CoverageSweepCandidate> candidates = dedupeEndpoints
            ? new ArrayList<>(deduped.values()) : imported;
        candidates.sort(Comparator.comparing(CoverageSweepCandidate::displayUrl,
                Comparator.nullsLast(String::compareTo)).thenComparing(CoverageSweepCandidate::method));
        return new CoverageSweepPreview(operations.size(), deduped.size(), List.copyOf(candidates));
    }

    public List<CoverageSweepProbe> buildProbes(CoverageSweepCandidate candidate, CoverageSweepOptions options) {
        if (candidate == null) {
            return List.of();
        }
        CoverageSweepOptions effective = options == null ? CoverageSweepOptions.defaults() : options;
        ConfiguredHeaderPolicy headerPolicy = new ConfiguredHeaderPolicy(
            effective.requestHeaders(), effective.userAgentMode(),
            effective.userAgentRandomizationSeed());
        if (effective.mode() == CoverageSweepMode.AUTHENTICATED_TRAFFIC) {
            HttpRequest anonymousRequest = stripAuthentication(candidate.request(), effective.authSelection());
            return reconcileProbes(generateProbes(anonymousRequest, effective, false),
                anonymousRequest, headerPolicy.withoutAuthentication(effective.authSelection().headerNames(), effective.authSelection().cookieNames()), effective);
        }
        return reconcileProbes(generateProbes(candidate.request(), effective, true),
            candidate.request(), headerPolicy, effective);
    }

    private List<CoverageSweepProbe> generateProbes(HttpRequest request,
                                                     CoverageSweepOptions options,
                                                     boolean includeControl) {
        if (options.payloadSet() == CoverageSweepPayloadSet.ALL_PAYLOADS) {
            return fullProbeGenerator.buildProbes(request,includeControl,options.familySelection(),running ? live : null);
        }
        return probeGenerator.buildProbes(request, options, includeControl);
    }

    public boolean start(List<CoverageSweepCandidate> candidates,
                         CoverageSweepOptions options,
                         Consumer<AttackResult> resultCallback,
                         Runnable completionCallback) {
        if (running || candidates == null || candidates.isEmpty()
            || candidates.stream().anyMatch(candidate -> !candidate.unresolvedVariables().isEmpty())) {
            return false;
        }

        CoverageSweepOptions effectiveOptions = options == null ? CoverageSweepOptions.defaults() : options;
        var inventory=effectiveOptions.payloadSet()==CoverageSweepPayloadSet.ALL_PAYLOADS ? BypassPlaybooks.Inventory.BYPASS : BypassPlaybooks.Inventory.HIGH_SIGNAL;
        Set<String> families=inventory==BypassPlaybooks.Inventory.BYPASS ? effectiveOptions.familySelection().bypassFamilies().stream().map(com.bypassfuzzer.burp.core.attacks.AttackType::id).collect(java.util.stream.Collectors.toSet()) : effectiveOptions.familySelection().highSignalFamilies();
        live=new LiveRun(new RunConfiguration(Set.of(),effectiveOptions.concurrency(),Math.min(effectiveOptions.concurrency(),effectiveOptions.perHostConcurrency()),400,
            BypassPlaybooks.resolve(inventory,families,effectiveOptions.playbookOptions()),effectiveOptions.requestHeaders(),Set.of(),effectiveOptions.userAgentMode(),effectiveOptions.userAgentRandomizationSeed()),RunPlans.bypass(inventory));
        candidates.forEach(c -> live.registerHost(c.host()));liveMemories.clear();
        pauseController.reset();
        failedCandidates.set(0);
        failures.clear();
        failedSweepHosts.clear();
        sweepHosts.clear();
        completedSweepHosts.clear();
        pendingHostCandidates.clear();
        plannedMainRequests.set(0);
        skippedPublicEndpoints.set(0);
        completedMainRequests.set(0);
        sentRequests.set(0);
        automaticRetryRequests.set(0);
        quarantinedRetryRequests.set(0);
        phase = SweepPhase.PREPARING;
        running = true;
        runnerThread = new Thread(() -> {
            try {
                execute(candidates, effectiveOptions, resultCallback);
            } catch (RuntimeException | LinkageError error) {
                if (running && !Thread.currentThread().isInterrupted()) recordFailure("Sweep setup", error);
            } finally {
                running = false;
                phase = Thread.currentThread().isInterrupted() || phase == SweepPhase.STOPPED
                    ? SweepPhase.STOPPED : failures.isEmpty() ? SweepPhase.COMPLETE : SweepPhase.FAILED;
                if (completionCallback != null) {
                    completionCallback.run();
                }
            }
        }, "bypassfuzzer-coverage-sweep");
        runnerThread.setDaemon(true);
        runnerThread.start();
        return true;
    }

    public void stop() {
        if(live!=null)live.stop();
        running = false;
        phase = SweepPhase.STOPPED;
        ScanEngine currentScan = coreScan;
        if (currentScan != null) currentScan.stop();
        HostThrottleCoordinator currentCoordinator = coordinator;
        if (currentCoordinator != null) currentCoordinator.manualResume();
        pauseController.resume();
        if (executor != null) {
            executor.shutdownNow();
        }
        if (runnerThread != null) {
            runnerThread.interrupt();
        }
    }

    public void cleanup() {
        stop();
        deferredRetryQueue.clear();
        if (runnerThread != null && runnerThread.isAlive()) {
            try {
                runnerThread.join(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    public boolean isRunning() {
        return running;
    }

    public LiveRun liveRun(){return live;}
    public void pause() {
        if (!running) return;
        if(live!=null){live.pause();return;}
        ScanEngine currentScan = coreScan;
        if (currentScan != null) currentScan.pause();
        pauseController.pause();
        HostThrottleCoordinator currentCoordinator = coordinator;
        if (currentCoordinator != null) currentCoordinator.manualPause();
    }

    public void resume() {
        if(live!=null){live.resume();return;}
        ScanEngine currentScan = coreScan;
        if (currentScan != null) currentScan.resume();
        HostThrottleCoordinator currentCoordinator = coordinator;
        if (currentCoordinator != null) currentCoordinator.manualResume();
        pauseController.resume();
    }
    public boolean isPaused() { return live!=null ? live.snapshot().state()==LiveRun.State.PAUSED || live.snapshot().state()==LiveRun.State.PAUSING : pauseController.isPaused(); }

    public int inFlightRequestCount() {
        HostThrottleCoordinator currentCoordinator = coordinator;
        return currentCoordinator == null ? 0 : currentCoordinator.inFlightRequestCount();
    }

    public int completedHostCount() {
        return completedSweepHosts.size();
    }

    public int totalHostCount() {
        return sweepHosts.size();
    }

    public SweepPhase phase() {
        return phase;
    }

    public int failedCandidateCount() { return failedCandidates.get(); }

    public List<String> failureMessages() { return List.copyOf(failures); }

    private void recordFailure(String target, Throwable error) {
        String detail = error.getClass().getSimpleName()
            + (error.getMessage() == null ? "" : ": " + error.getMessage());
        String message = target + " — " + detail;
        failures.offer(message);
        safeLogError("Coverage sweep failed: " + message);
    }

    public int plannedMainRequestCount() {
        return plannedMainRequests.get();
    }

    public int skippedPublicEndpointCount() {
        return skippedPublicEndpoints.get();
    }

    public int completedMainRequestCount() {
        return completedMainRequests.get();
    }

    public int sentRequestCount() {
        return live==null ? sentRequests.get() : (int)Math.min(Integer.MAX_VALUE,live.snapshot().requestsSent());
    }

    public int automaticRetryRequestCount() {
        return automaticRetryRequests.get();
    }

    public int quarantinedRetryRequestCount() {
        return quarantinedRetryRequests.get();
    }

    public List<String> completedHostSnapshot() {
        return completedSweepHosts.stream().sorted(String.CASE_INSENSITIVE_ORDER).toList();
    }

    public int deferredRetryCount() {
        return deferredRetryQueue.size();
    }

    public List<AttackResult> deferredRetrySnapshot() {
        return deferredRetryQueue.stream().map(RetryTask::result).toList();
    }

    public List<CoverageSweepRetryItem> deferredRetryItemSnapshot() {
        return deferredRetryQueue.stream()
            .map(item -> new CoverageSweepRetryItem(item.result(), item.probe()))
            .toList();
    }

    private void execute(List<CoverageSweepCandidate> candidates,
                         CoverageSweepOptions initialOptions,
                         Consumer<AttackResult> resultCallback) {
      while(canContinue()) {
        var generationSnapshot=live.snapshot();generation=generationSnapshot.revision();headerGeneration=generationSnapshot.headerRevision();
        plannedMainRequests.set(completedMainRequests.get());pendingHostCandidates.clear();
        completedSweepHosts.removeIf(host -> live.snapshot().configuration().excludes(host));
        CoverageSweepOptions options=initialOptions.withRunConfiguration(live.snapshot().configuration());
        ThrottleSettings throttleSettings = options.throttleSettings();
        coordinator = new HostThrottleCoordinator(throttleSettings, api);
        coreScan = new ScanEngine(new ScanOptions(HttpProtocol.AUTO, Duration.ofSeconds(15),
            throttleSettings.globalConcurrency(), throttleSettings.perHostConcurrency(),
            options.throttleStatusCodes(), 0, false, options.posture().name().toLowerCase(),
            options.pauseMode().name().toLowerCase(), options.fixedPauseMillis(), false),false,live);
        phase = SweepPhase.MAIN_SWEEP;
        int concurrency = throttleSettings.globalConcurrency();
        safeLog("Coverage sweep starting: " + candidates.size() + " candidate(s); adaptive rate control, "
            + "global in-flight: " + concurrency + "; per-host in-flight: " + throttleSettings.perHostConcurrency()
            + "; payload set: "
            + options.payloadSet() + (options.payloadSet() == CoverageSweepPayloadSet.ALL_PAYLOADS
                ? " (uncapped full Bypass catalog)" : " (bounded high-signal probes)"));
        AtomicInteger workerCounter = new AtomicInteger(1);
        executor = Executors.newFixedThreadPool(concurrency, runnable -> {
            Thread thread = new Thread(runnable, "bypassfuzzer-coverage-sweep-worker-" + workerCounter.getAndIncrement());
            thread.setDaemon(true);
            return thread;
        });
        ConcurrentLinkedQueue<RetryTask> retryQueue = new ConcurrentLinkedQueue<>(deferredRetryQueue);
        deferredRetryQueue = retryQueue;
        for (CoverageSweepCandidate candidate : candidates) {
            String candidateHost = host(candidate.request(), candidate.displayUrl());
            sweepHosts.add(candidateHost);
            pendingHostCandidates.computeIfAbsent(candidateHost, ignored -> new AtomicInteger()).incrementAndGet();
        }

        // Workers pull candidates from a shared cursor. Probe lists therefore exist only for active
        // candidates instead of materializing the complete scan before the first request is sent.
        List<CoverageSweepCandidate> interleaved = interleaveCandidatesByHost(candidates);
        AtomicInteger nextCandidate = new AtomicInteger();
        int workerCount = Math.min(concurrency, interleaved.size());
        for (int worker = 0; worker < workerCount; worker++) {
            executor.submit(() -> {
                while (canContinue()) {
                    int candidateIndex = nextCandidate.getAndIncrement();
                    if (candidateIndex >= interleaved.size()) {
                        return;
                    }
                    CoverageSweepCandidate candidate = interleaved.get(candidateIndex);
                    try {
                        executeCandidate(candidate, options, resultCallback, retryQueue);
                    } catch (LiveRun.Reconfigured changed) {
                        // The run resumes with a fresh plan and its completed-work memory.
                    } catch (java.util.concurrent.CancellationException stopped) {
                        // Stop releases paused workers without manufacturing transport errors.
                    } catch (Exception | LinkageError error) {
                        if (running && !Thread.currentThread().isInterrupted()) {
                            failedCandidates.incrementAndGet();
                            failedSweepHosts.add(host(candidate.request(), candidate.displayUrl()));
                            recordFailure(candidate.method() + " " + candidate.displayUrl(), error);
                        }
                    } finally {
                        String candidateHost = host(candidate.request(), candidate.displayUrl());
                        AtomicInteger remaining = pendingHostCandidates.get(candidateHost);
                        if (remaining != null && remaining.decrementAndGet()==0 && !failedSweepHosts.contains(candidateHost) && !live.snapshot().configuration().excludes(candidateHost)) {
                            completedSweepHosts.add(candidateHost);
                        }
                    }
                }
            });
        }

        executor.shutdown();
        try {
            while (canContinue() && !executor.awaitTermination(200, TimeUnit.MILLISECONDS)) {
                // Wait for workers to finish or for stop() to interrupt this runner.
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            if (!executor.isTerminated()) {
                executor.shutdownNow();
            }
        }
        if(canContinue() && live.snapshot().revision()!=generation)continue;
        retryQueue.removeIf(r -> !live.allowed(r.probe().request().httpService().host(),r.result().getTargetLabel()) || !live.selected(r.probe().playbookId()));
        if (canContinue() && !retryQueue.isEmpty()) {
            phase = SweepPhase.AUTOMATIC_RETRIES;
        }
        try {
            runDeferredRetries(retryQueue,options,resultCallback,concurrency);
            if(canContinue())live.checkpoint(generation);
        }catch(LiveRun.Reconfigured changed){continue;}
        catch(java.util.concurrent.CancellationException stopped){break;}
        safeLog("Coverage sweep worker pool finished: " + candidates.size() + " candidate(s) submitted; payload set: "
            + options.payloadSet() + "; deferred retries remaining: " + retryQueue.size());
        break;
      }
    }

    private void executeCandidate(CoverageSweepCandidate originalCandidate,CoverageSweepOptions options,
        Consumer<AttackResult> resultCallback,ConcurrentLinkedQueue<RetryTask> retryQueue) {
        live.checkpoint(generation);
        String seed=originalCandidate.method()+" "+originalCandidate.displayUrl();
        if(!live.allowed(originalCandidate.host(),seed))return;
        live.planningSeed(originalCandidate.dedupeKey()+"\n"+originalCandidate.request().toString());
        var config=live.snapshot().configuration();
        HttpRequest prepared=config.prepare(originalCandidate.request(),com.bypassfuzzer.burp.http.MontoyaRequestAccess.INSTANCE);
        HttpResponse captured=originalCandidate.originalResponse();
        if(options.mode()==CoverageSweepMode.AUTHENTICATED_TRAFFIC && headerGeneration>0) {
            final HttpRequest captureRequest=prepared;
            var capture=refreshedCaptures.get(seed+"\n"+headerGeneration,() -> java.util.Optional.ofNullable(sendScheduled(captureRequest,() -> requestSender.sendManaged(captureRequest,null,15,TimeUnit.SECONDS,this::canContinue,live,generation))));
            captured=capture.value().orElse(null);
            if(capture.fresh() && resultCallback!=null)resultCallback.accept(new AttackResult("Authenticated Coverage Sweep","Authenticated control after configuration edit",seed,"Control","Control",prepared,captured));
        }
        final CoverageSweepCandidate candidate=new CoverageSweepCandidate(prepared,captured,originalCandidate.dedupeKey(),originalCandidate.displayUrl(),originalCandidate.method(),originalCandidate.host(),originalCandidate.path(),
            captured==null ? originalCandidate.statusCode() : captured.statusCode(),captured==null ? originalCandidate.contentLength() : bodyLength(captured),captured==null ? originalCandidate.contentType() : contentType(captured),originalCandidate.time());
        var memory=liveMemories.computeIfAbsent(seed,ignored -> new com.bypassfuzzer.core.scan.SweepWorkflow.Memory<>());
        memory.context(headerGeneration);
        var workflow = new com.bypassfuzzer.core.scan.SweepWorkflow<HttpRequest, HttpResponse>(
            com.bypassfuzzer.burp.http.MontoyaRequestAccess.INSTANCE, CoverageSweepClassifier::toCore);
        var policy = new ConfiguredHeaderPolicy(options.requestHeaders(), options.userAgentMode(),
            options.userAgentRandomizationSeed());
        var execution = new com.bypassfuzzer.core.scan.SweepWorkflow.Options(
            options.mode() == CoverageSweepMode.AUTHENTICATED_TRAFFIC,
            options.verifyUnauthenticatedAccess(), options.skipLikelyPublicEndpoints(),
            options.authSelection().headerNames(), options.authSelection().cookieNames(), options.playbookOptions().wildcardCalibration(), options.throttleStatusCodes());
        var input = new com.bypassfuzzer.core.scan.SweepWorkflow.Candidate<>(candidate.request(),
            candidate.originalResponse(), candidate.method() + " " + candidate.displayUrl(),
            new com.bypassfuzzer.core.scan.SweepClassifier.Baseline(candidate.statusCode(), candidate.contentLength(), candidate.contentType()),
            coreRequests.fromMontoya(candidate.request()).protocol());
        workflow.execute(input, execution, policy.shared(), () -> buildProbes(candidate, options).stream()
            .map(probe -> new com.bypassfuzzer.core.scan.SweepWorkflow.Probe<>(probe.label(), probe.family(),
                probe.request(), probe.httpMode() == burp.api.montoya.http.HttpMode.HTTP_2 ? HttpProtocol.HTTP_2
                    : probe.httpMode() == burp.api.montoya.http.HttpMode.HTTP_1 ? HttpProtocol.HTTP_1 : HttpProtocol.AUTO, probe.playbookId(), probe.controlRole())).toList(),
            probe -> sendScheduled(probe.request(), () -> requestSender.sendManaged(probe.request(),coreRequests.httpMode(probe.protocol()),15,TimeUnit.SECONDS,this::canContinue,live,generation)), this::canContinue,
            new com.bypassfuzzer.core.scan.SweepWorkflow.Observer<HttpRequest, HttpResponse>() {
                public void planned(int count) { plannedMainRequests.addAndGet(count); }
                public void completed() { completedMainRequests.incrementAndGet(); }
                public void skippedPublic() { skippedPublicEndpoints.incrementAndGet(); }
                public void result(com.bypassfuzzer.core.scan.SweepWorkflow.Result<HttpRequest, HttpResponse> event) {
                    AttackResult result = new AttackResult(event.attackType(), event.probe().label(), event.target(),
                        event.probe().family(), event.signal(), event.probe().request(), event.response(),
                        event.originalRequest(), event.originalResponse(), event.verificationRequest(), event.verificationResponse())
                        .withEvidenceMetadata(new AttackResult.EvidenceMetadata(event.probe().playbookId(), event.probe().controlRole(),
                            event.calibration(),event.fallbackRequest(),event.fallbackResponse(),event.context()).withRun(null,generation)).copyEvidenceToTempFile();
                    if (resultCallback != null) resultCallback.accept(result);
                    // The master's anonymous verification control is evidence, not deferred mutation work.
                    if (!event.probe().family().equals("Unauthenticated Control") && isRetryableResponse(event.response(), options))
                        retryQueue.add(new RetryTask(result, new CoverageSweepProbe(event.probe().label(), event.probe().family(),
                            event.probe().request(), coreRequests.httpMode(event.probe().protocol()), event.probe().playbookId(), event.probe().controlRole())));
                }
            },memory);
    }

    private void runDeferredRetries(ConcurrentLinkedQueue<RetryTask> retryQueue, CoverageSweepOptions options,
        Consumer<AttackResult> resultCallback, int concurrency) {
        new com.bypassfuzzer.core.scan.DeferredRetryRunner<RetryTask>().run(retryQueue,
            com.bypassfuzzer.core.scan.ScanDefaults.SWEEP_RETRIES, concurrency, this::canContinue,
            item -> retryGroupKey(item).authority(), item -> retryGroupKey(item).family(), item -> {
                var current=currentRetry(item);
                HttpRequest control=current.result().getOriginalRequest()==null ? current.probe().request() : current.result().getOriginalRequest();
                HttpResponse response = sendScheduled(control, () -> requestSender.sendManaged(control,null,15,TimeUnit.SECONDS,this::canContinue,live,generation));
                return canContinue() && response != null && !isThrottleResponse(response, options);
            }, (item, attempt) -> executeDeferredRetry(item, attempt, options, resultCallback, retryQueue),
            quarantinedRetryRequests::addAndGet, this::safeLog);
    }

    private RetryTask currentRetry(RetryTask retry) {
        CoverageSweepProbe probe=retry.probe();
        AttackResult previous=retry.result();
        var memory=liveMemories.get(previous.getTargetLabel());
        var template=memory==null ? null : memory.latest(new com.bypassfuzzer.core.scan.SweepWorkflow.Probe<>(probe.label(),probe.family(),probe.request(),coreRequests.fromMontoya(probe.request()).protocol(),probe.playbookId(),probe.controlRole()));
        if(template!=null) {
            probe=new CoverageSweepProbe(template.probe().label(),template.probe().family(),template.probe().request(),coreRequests.httpMode(template.probe().protocol()),template.probe().playbookId(),template.probe().controlRole());
            previous=new AttackResult(template.attackType(),template.probe().label(),template.target(),template.probe().family(),template.signal(),template.probe().request(),null,template.originalRequest(),template.originalResponse(),template.verificationRequest(),template.verificationResponse())
                .withEvidenceMetadata(new AttackResult.EvidenceMetadata(template.probe().playbookId(),template.probe().controlRole(),template.calibration(),template.fallbackRequest(),template.fallbackResponse(),template.context()));
        }
        return new RetryTask(previous,probe);
    }

    private boolean executeDeferredRetry(RetryTask retry,
                                         int attempt,
                                         CoverageSweepOptions options,
                                         Consumer<AttackResult> resultCallback,
                                         ConcurrentLinkedQueue<RetryTask> retryQueue) {
        retry=currentRetry(retry);
        CoverageSweepProbe probe=retry.probe();
        AttackResult previous=retry.result();
        final CoverageSweepProbe currentProbe=probe;
        HttpResponse response = sendScheduled(probe.request(), () -> requestSender.sendManaged(currentProbe.request(),currentProbe.httpMode(),15,TimeUnit.SECONDS,this::canContinue,live,generation));
        AttackResult retryResult=AttackResult.throttleRetryOf(previous,response,attempt)
            .copyEvidenceToTempFile();
        if (resultCallback != null) {
            resultCallback.accept(retryResult);
        }
        boolean retryable = isRetryableResponse(response, options);
        if (retryable) {
            retryQueue.add(new RetryTask(retryResult, probe));
        }
        return retryable;
    }

    private RetryGroupKey retryGroupKey(RetryTask retry) {
        HttpRequest request = retry.probe().request();
        String authority = authorityKey(request, request == null ? "" : safeUrl(request));
        String family = safe(retry.result().getPayloadFamily());
        return new RetryGroupKey(authority, family.isBlank() ? safe(retry.probe().family()) : family);
    }

    private boolean isThrottleResponse(HttpResponse response, CoverageSweepOptions options) {
        // Ride-hard posture: any throttle-coded response is re-queued so coverage stays complete.
        return response != null
            && options.throttleStatusCodes().contains((int) response.statusCode());
    }

    private boolean isRetryableResponse(HttpResponse response, CoverageSweepOptions options) {
        // A null response means the payload was never observed reaching the target, just like a
        // throttle response. Preserve it for the automatic pass and, if needed, manual retry.
        return response == null || isThrottleResponse(response, options);
    }

    private record RetryTask(AttackResult result, CoverageSweepProbe probe) {
    }

    private boolean eligible(ProxyHttpRequestResponse item, CoverageSweepOptions options) {
        HttpRequest request = effectiveRequest(item);
        if (item == null || item.response() == null || request == null) {
            return false;
        }
        if (options.mode() == CoverageSweepMode.AUTHENTICATED_TRAFFIC) {
            int status = item.response().statusCode();
            if (status < 200 || status >= 300) {
                return false;
            }
            if (options.excludeStaticAssets() && isStaticAsset(request, item.response())) {
                return false;
            }
        } else if (!options.statuses().contains((int) item.response().statusCode())) {
            return false;
        }
        if (!options.inScopeOnly()) {
            return true;
        }
        try {
            return isInScope(item);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean hasSuccessfulResponse(ProxyHttpRequestResponse item) {
        HttpRequest request = effectiveRequest(item);
        if (item == null || request == null || item.response() == null) return false;
        int status = item.response().statusCode();
        return status >= 200 && status < 300;
    }

    private boolean isInScope(ProxyHttpRequestResponse item) {
        if (item == null) {
            return false;
        }

        // Scope belongs to the proxy-history transaction, not to one particular
        // Montoya view of it. In particular, HTTP/2 history entries can report a
        // different scope result from finalRequest() than Burp reports for the
        // history row's final URL. Check every Burp-owned representation and only
        // reject the row when all of them agree that it is out of scope.
        Set<String> urls = new LinkedHashSet<>();
        addScopeUrl(urls, proxyHistoryUrl(item));

        HttpRequest originalRequest = originalRequest(item);
        HttpRequest finalRequest = finalRequest(item);
        if (requestReportsInScope(originalRequest) || requestReportsInScope(finalRequest)) {
            return true;
        }
        addScopeUrl(urls, requestUrl(originalRequest));
        addScopeUrl(urls, requestUrl(finalRequest));

        for (String url : urls) {
            try {
                if (api.scope().isInScope(url)) {
                    return true;
                }
            } catch (RuntimeException | LinkageError ignored) {
            }
        }
        return false;
    }

    private boolean requestReportsInScope(HttpRequest request) {
        if (request == null) return false;
        try {
            return request.isInScope();
        } catch (RuntimeException | LinkageError ignored) {
            return false;
        }
    }

    @SuppressWarnings("removal")
    private String proxyHistoryUrl(ProxyHttpRequestResponse item) {
        try {
            return item.url();
        } catch (RuntimeException | LinkageError ignored) {
            return "";
        }
    }

    private String requestUrl(HttpRequest request) {
        if (request == null) return "";
        try {
            return safeUrl(request);
        } catch (RuntimeException | LinkageError ignored) {
            return "";
        }
    }

    private void addScopeUrl(Set<String> urls, String url) {
        if (url != null && !url.isBlank()) {
            urls.add(url);
        }
    }

    private HttpRequest originalRequest(ProxyHttpRequestResponse item) {
        if (item == null) return null;
        try {
            return item.request();
        } catch (RuntimeException | LinkageError ignored) {
            return null;
        }
    }

    private HttpRequest finalRequest(ProxyHttpRequestResponse item) {
        if (item == null) return null;
        try {
            return item.finalRequest();
        } catch (RuntimeException | LinkageError ignored) {
            return null;
        }
    }

    private HttpRequest effectiveRequest(ProxyHttpRequestResponse item) {
        HttpRequest finalRequest = finalRequest(item);
        return finalRequest != null ? finalRequest : originalRequest(item);
    }

    private boolean isStaticAsset(HttpRequest request, HttpResponse response) {
        return com.bypassfuzzer.core.scan.SweepCandidateRules.staticAsset(request == null ? "" : request.path(), contentType(response));
    }

    public boolean matchesAuthSelection(CoverageSweepCandidate candidate, CoverageSweepAuthSelection selection) {
        if (candidate == null || candidate.request() == null || selection == null) {
            return false;
        }
        for (String headerName : selection.headerNames()) {
            if (headerName != null && !headerName.isBlank() && candidate.request().hasHeader(headerName.trim())) {
                return true;
            }
        }
        String cookieHeader = candidate.request().headerValue("Cookie");
        if (cookieHeader == null) {
            return false;
        }
        Set<String> presentCookies = cookieNames(cookieHeader);
        return selection.cookieNames().stream().anyMatch(presentCookies::contains);
    }

    HttpRequest stripAuthentication(HttpRequest request, CoverageSweepAuthSelection selection) {
        return new com.bypassfuzzer.core.scan.SweepWorkflow<HttpRequest, HttpResponse>(
            com.bypassfuzzer.burp.http.MontoyaRequestAccess.INSTANCE, CoverageSweepClassifier::toCore)
            .stripAuthentication(request, selection == null ? Set.of() : selection.headerNames(),
                selection == null ? Set.of() : selection.cookieNames());
    }

    private List<CoverageSweepProbe> reconcileProbes(List<CoverageSweepProbe> probes,
                                                      HttpRequest baseline,
                                                      ConfiguredHeaderPolicy headerPolicy,
                                                      CoverageSweepOptions options) {
        return probes.stream()
            .map(probe -> {
                HttpRequest reconciled = headerPolicy.reconcileMutation(baseline, probe.request());
                return new CoverageSweepProbe(
                    probe.label(), probe.family(), reconciled, probe.httpMode(), probe.playbookId(), probe.controlRole());
            })
            .toList();
    }

    private void collectAuthIdentifiers(HttpRequest request, Set<String> headers, Set<String> cookies) {
        try {
            for (HttpHeader header : request.headers()) {
                String name = header.name();
                if (looksLikeAuthHeader(name)) {
                    headers.add(name);
                }
            }
        } catch (Exception ignored) {
        }
        cookies.addAll(cookieNames(request.headerValue("Cookie")));
    }

    private boolean looksLikeAuthHeader(String name) {
        String lower = safe(name).toLowerCase(Locale.ROOT);
        return lower.equals("authorization") || lower.equals("proxy-authorization")
            || lower.contains("auth") || lower.contains("token") || lower.contains("api-key")
            || lower.contains("apikey") || lower.contains("session");
    }

    private Set<String> cookieNames(String cookieHeader) {
        if (cookieHeader == null || cookieHeader.isBlank()) {
            return Set.of();
        }
        Set<String> names = new TreeSet<>();
        for (String cookie : cookieHeader.split(";")) {
            int separator = cookie.indexOf('=');
            String name = (separator >= 0 ? cookie.substring(0, separator) : cookie).trim();
            if (!name.isBlank()) names.add(name);
        }
        return names;
    }


    private CoverageSweepCandidate toCandidate(ProxyHttpRequestResponse item) {
        HttpRequest request = effectiveRequest(item);
        HttpResponse response = item.response();
        if (request == null || response == null) {
            return null;
        }

        String displayUrl = safeUrl(request);
        String path = request.path() == null || request.path().isBlank() ? RequestPathUtils.extractPathAndQuery(displayUrl) : request.path();
        return new CoverageSweepCandidate(
            request,
            response,
            dedupeKey(request, displayUrl),
            displayUrl,
            safe(request.method()),
            host(request, displayUrl),
            path,
            response.statusCode(),
            bodyLength(response),
            contentType(response),
            item.time()
        );
    }

    private CoverageSweepCandidate toImportedCandidate(String rawUrl) {
        String displayUrl = normalizeUrl(rawUrl);
        if (displayUrl == null) {
            return null;
        }

        try {
            URI uri = URI.create(displayUrl);
            HttpRequest request = urlRequestFactory.create(uri);
            String path = request.path() == null || request.path().isBlank() ? RequestPathUtils.extractPathAndQuery(displayUrl) : request.path();
            return new CoverageSweepCandidate(
                request,
                null,
                dedupeKey(request, displayUrl),
                displayUrl,
                safe(request.method()),
                host(request, displayUrl),
                path,
                0,
                0,
                "",
                ZonedDateTime.now()
            );
        } catch (Exception e) {
            return null;
        }
    }

    private CoverageSweepCandidate toImportedCandidate(OpenApiOperation operation) {
        try {
            URI uri = OpenApiOperation.previewUri(operation.url());
            if (normalizeUrl(uri.toString()) == null) return null;
            boolean unresolved = !operation.unresolvedVariables().isEmpty();
            HttpRequest request = urlRequestFactory.create(uri).withMethod(operation.method());
            if (unresolved) {
                request = request.withPath(operation.requestTarget());
                request = RequestHeaderUtils.upsertHeader(request, "Host", operation.authority());
            }
            for (Map.Entry<String, String> header : operation.headers().entrySet()) {
                request = RequestHeaderUtils.upsertHeader(request, header.getKey(), header.getValue());
            }
            if (!operation.body().isEmpty()) request = request.withBody(operation.body());
            String path = request.path() == null || request.path().isBlank()
                ? operation.requestTarget() : request.path();
            String key = dedupeKey(request, uri.toString());
            String importKey = "";
            if (operation.source() != null) {
                String prefix = operation.method() + "\u0000" + operation.source().server() + "\u0000";
                importKey = prefix + operation.source().path();
                key = prefix + normalizedPathShape(operation.source().path().replaceAll("\\{[^}/]+}", "1"));
            }
            return new CoverageSweepCandidate(request, null, key, operation.url(),
                safe(request.method()), unresolved ? operation.authority() : host(request, operation.url()),
                path, 0, 0, safe(request.headerValue("Content-Type")), ZonedDateTime.now(),
                importKey, operation.unresolvedVariables());
        } catch (Exception e) {
            return null;
        }
    }

    private static HttpRequest defaultImportedRequest(URI uri) {
        boolean secure = "https".equalsIgnoreCase(uri.getScheme());
        int port = uri.getPort() > 0 ? uri.getPort() : (secure ? 443 : 80);
        String path = uri.getRawPath() == null || uri.getRawPath().isBlank() ? "/" : uri.getRawPath();
        if (uri.getRawQuery() != null && !uri.getRawQuery().isBlank()) {
            path += "?" + uri.getRawQuery();
        }

        HttpService service = HttpService.httpService(uri.getHost(), port, secure);
        String rawRequest = "GET " + path + " HTTP/1.1\r\n"
            + "Host: " + hostHeader(uri.getHost(), port, secure) + "\r\n"
            + "\r\n";
        return HttpRequest.httpRequest(service, rawRequest);
    }

    private static String hostHeader(String host, int port, boolean secure) {
        if ((secure && port == 443) || (!secure && port == 80)) {
            return host;
        }
        return host + ":" + port;
    }

    private String normalizeUrl(String rawUrl) {
        if (rawUrl == null) {
            return null;
        }
        String trimmed = rawUrl.trim();
        if (trimmed.isBlank() || trimmed.startsWith("#")) {
            return null;
        }
        try {
            URI uri = URI.create(trimmed);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            if (host == null || (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))) {
                return null;
            }
            return uri.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private String dedupeKey(HttpRequest request, String displayUrl) {
        return authorityKey(request, displayUrl)
            + "|" + safe(request.method()).toUpperCase(Locale.ROOT)
            + "|" + normalizedPathShape(request.path());
    }

    private String authorityKey(HttpRequest request, String displayUrl) {
        HttpService service = request.httpService();
        if (service != null && service.host() != null) {
            return (service.secure() ? "https" : "http") + "://" + service.host().toLowerCase(Locale.ROOT) + ":" + service.port();
        }
        try {
            URI uri = URI.create(displayUrl);
            int port = uri.getPort() > 0 ? uri.getPort() : ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80);
            return safe(uri.getScheme()).toLowerCase(Locale.ROOT) + "://" + safe(uri.getHost()).toLowerCase(Locale.ROOT) + ":" + port;
        } catch (Exception e) {
            return displayUrl;
        }
    }

    private String normalizedPathShape(String path) {
        return com.bypassfuzzer.core.scan.SweepCandidateRules.normalizedPathShape(path);
    }

    private boolean newer(ZonedDateTime left, ZonedDateTime right) {
        if (left == null) {
            return false;
        }
        if (right == null) {
            return true;
        }
        return left.isAfter(right);
    }

    private String safeUrl(HttpRequest request) {
        try {
            return targetUrlResolver.resolve(request);
        } catch (Exception e) {
            return request.url();
        }
    }

    private String host(HttpRequest request, String displayUrl) {
        try {
            if (request.httpService() != null && request.httpService().host() != null) {
                return request.httpService().host();
            }
        } catch (Exception e) {
            // Fall back to URL parsing.
        }
        try {
            return URI.create(displayUrl).getHost();
        } catch (Exception e) {
            return "";
        }
    }

    private String contentType(HttpResponse response) {
        return response.headers().stream()
            .filter(header -> header.name().equalsIgnoreCase("Content-Type"))
            .map(HttpHeader::value)
            .findFirst()
            .orElse("");
    }

    private int bodyLength(HttpResponse response) {
        return response.body() == null ? 0 : response.body().length();
    }

    private boolean canContinue() {
        return running && !Thread.currentThread().isInterrupted();
    }

    private boolean awaitSendAdmission() {
        if(live!=null){live.checkpoint(generation);return canContinue();}
        return pauseController.awaitIfPaused(this::canContinue);
    }

    private HttpResponse sendScheduled(HttpRequest request, java.util.function.Supplier<HttpResponse> sender) {
        if (!awaitSendAdmission()) {
            return null;
        }
        java.util.function.Supplier<HttpResponse> countedSender=() -> {
            java.util.concurrent.Callable<HttpResponse> physical=() -> {
                sentRequests.incrementAndGet();if(phase==SweepPhase.AUTOMATIC_RETRIES)automaticRetryRequests.incrementAndGet();return sender.get();
            };
            try{return physical.call();}
            catch(LiveRun.Reconfigured | java.util.concurrent.CancellationException error){throw error;}
            catch(Exception error){throw new java.util.concurrent.CompletionException(error);}
        };
        HostThrottleCoordinator currentCoordinator = coordinator;
        ScanEngine currentScan = coreScan;
        if (currentScan == null) return null;
        return currentScan.exchange(coreRequests.fromMontoya(request), () -> currentCoordinator == null
            ? (awaitSendAdmission() ? countedSender.get() : null)
            : currentCoordinator.send(request, countedSender,
                this::awaitSendAdmission),response -> response.statusCode()).response();
    }

    private void safeLog(String message) {
        try {
            if (api != null && api.logging() != null) api.logging().logToOutput(message);
        } catch (Exception ignored) {
        }
    }

    private void safeLogError(String message) {
        try {
            if (api != null && api.logging() != null) api.logging().logToError(message);
        } catch (Exception ignored) {
        }
    }

    private String safe(String value) {
        return value == null ? "" : value;
    }

    /** Round-robin interleave candidates so all hosts make progress concurrently. */
    private List<CoverageSweepCandidate> interleaveCandidatesByHost(List<CoverageSweepCandidate> candidates) {
        return com.bypassfuzzer.core.scan.CandidateScheduler.interleave(candidates,
            candidate -> host(candidate.request(), candidate.displayUrl()));
    }

    private record RetryGroupKey(String authority, String family) {
    }

    @FunctionalInterface
    interface UrlRequestFactory {
        HttpRequest create(URI uri);
    }
}
