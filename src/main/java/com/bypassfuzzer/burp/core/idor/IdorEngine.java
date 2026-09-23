package com.bypassfuzzer.burp.core.idor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.throttle.GlobalTrafficGovernor;
import com.bypassfuzzer.burp.core.throttle.HostThrottleCoordinator;
import com.bypassfuzzer.burp.http.BurpScanAdapter;
import com.bypassfuzzer.burp.http.CoreRequestAdapter;
import com.bypassfuzzer.burp.http.ConfiguredHeaderPolicy;
import com.bypassfuzzer.burp.http.MontoyaRequestSender;
import com.bypassfuzzer.burp.http.RequestSender;
import com.bypassfuzzer.core.http.HttpProtocol;
import com.bypassfuzzer.core.scan.IdorPlanOptions;
import com.bypassfuzzer.core.scan.IdorPlanner;
import com.bypassfuzzer.core.scan.ScanOptions;
import com.bypassfuzzer.core.scan.ResponseGuidedIdorPlanner;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import com.bypassfuzzer.core.scan.ScanEngine;

/** Burp session lifecycle around the shared IDOR planner and scan engine. */
public final class IdorEngine {
    private final MontoyaApi api;
    private final RequestSender sender;
    private volatile BurpScanAdapter adapter;
    private volatile Thread runner;
    private volatile boolean running;
    private volatile String lastDiagnostic;

    public IdorEngine(MontoyaApi api) { this(api, new GlobalTrafficGovernor()); }

    public IdorEngine(MontoyaApi api, GlobalTrafficGovernor governor) {
        this.api = api;
        this.sender = new MontoyaRequestSender(api, governor);
    }

    IdorEngine(RequestSender sender) { this(null, sender); }

    IdorEngine(MontoyaApi api, RequestSender sender) { this.api = api; this.sender = sender; }

    public synchronized boolean start(HttpRequest request, IdorOptions options,
                                      Consumer<AttackResult> results, Runnable completion) {
        if (running) return false;
        if (request == null || options == null || options.runOptions() == null) return false;
        int global = options.runOptions().concurrency();
        HttpProtocol requestProtocol = new CoreRequestAdapter().fromMontoya(request).protocol();
        ScanOptions execution = new ScanOptions(requestProtocol, Duration.ofSeconds(15), global,
            options.runOptions().perHostConcurrency(), options.runOptions().throttleStatusCodes(),
            1, false, options.runOptions().posture().name().equals("CONSERVATIVE") ? "conservative" : "ride-hard",
            options.runOptions().pauseMode().name().toLowerCase().replace('_', '-'),
            options.runOptions().fixedPauseMillis());
        ConfiguredHeaderPolicy headers = new ConfiguredHeaderPolicy(options.runOptions().requestHeaders(),
            options.runOptions().userAgentMode(), options.runOptions().userAgentRandomizationSeed());
        adapter = new BurpScanAdapter(request, sender, execution,
            api == null ? null : new HostThrottleCoordinator(options.runOptions().throttleSettings(), api),
            mutated -> headers.reconcileMutation(request, mutated));
        IdorPlanOptions plan = new IdorPlanOptions(options.normalizedAuthorizedIdentifier(),
            options.normalizedTargetIdentifier(), options.locationKey(), options.selectedFamilies(),
            options.maxMutations(), options.includeMethodChanges(), options.uniqueJsonPointer(),
            options.uniqueToken());
        lastDiagnostic = null;
        running = true;
        runner = new Thread(() -> {
            try {
                AtomicReference<AttackResult> authorizedBaseline = new AtomicReference<>();
                AtomicReference<AttackResult> targetBaseline = new AtomicReference<>();
                Consumer<AttackResult> trackedResults = result -> {
                    if ("idor.baseline.control".equals(result.getPayload())) authorizedBaseline.set(result);
                    if ("idor.baseline.target".equals(result.getPayload())) targetBaseline.set(result);
                    results.accept(result);
                };
                ResponseGuidedIdorPlanner guided = new ResponseGuidedIdorPlanner();
                ScanEngine.Summary summary;
                if (guided.enabled(plan)) summary = adapter.run("idor",
                    base -> guided.initialPlan(base, plan),
                    (base, authorized, target) -> guided.plan(base, plan, authorized, target), trackedResults);
                else summary = adapter.run("idor", base -> new IdorPlanner().plan(base, plan), trackedResults);
                if (running && summary.records() == 2 && summary.requestsSent() == 2) {
                    lastDiagnostic = baselineStopDiagnostic(authorizedBaseline.get(), targetBaseline.get());
                    logDiagnostic(lastDiagnostic);
                }
            } catch (Exception error) {
                lastDiagnostic = "IDOR scan failed after " + httpRequestsSent()
                    + " HTTP request(s): " + error.getClass().getSimpleName();
                logFailure(lastDiagnostic, error);
            } finally {
                running = false;
                if (completion != null) completion.run();
            }
        }, "bypassfuzzer-idor");
        runner.setDaemon(true);
        runner.start();
        return true;
    }

    public void stop() { if (adapter != null) adapter.stop(); if (runner != null) runner.interrupt(); running = false; }
    public void cleanup() { stop(); if (runner != null && runner.isAlive()) try { runner.join(2_000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); } }
    public boolean isRunning() { return running; }
    public void pause() { if (adapter != null) adapter.pause(); }
    public void resume() { if (adapter != null) adapter.resume(); }
    public boolean isPaused() { return adapter != null && adapter.isPaused(); }
    public long httpRequestsSent() { return adapter == null ? 0 : adapter.requestsSent(); }
    public String lastDiagnostic() { return lastDiagnostic; }

    private String baselineStopDiagnostic(AttackResult authorized, AttackResult target) {
        if (authorized == null || target == null) return "IDOR ended after two baselines without mutation results; inspect both baselines.";
        if (authorized.getResponse() == null) return "IDOR mutations skipped: authorized control had no response.";
        int controlStatus = authorized.getStatusCode();
        if (controlStatus < 200 || controlStatus >= 300)
            return "IDOR mutations skipped: authorized control returned HTTP " + controlStatus + ".";
        if (target.getResponse() == null) return "IDOR mutations skipped: target baseline had no response.";
        int targetStatus = target.getStatusCode();
        if (targetStatus >= 200 && targetStatus < 300)
            return "IDOR sent only the two baselines despite a target HTTP " + targetStatus
                + "; no mutation requests were applicable to the selected playbooks.";
        if (targetStatus != 401 && targetStatus != 403 && targetStatus != 404)
            return "IDOR mutations skipped: target baseline returned HTTP " + targetStatus
                + "; ordinary mutations require a 401, 403, or 404 target baseline.";
        return "IDOR sent only the two baselines: no mutation requests were applicable to the selected playbooks.";
    }

    private void logDiagnostic(String message) {
        try {
            if (api != null && api.logging() != null) api.logging().logToError(message);
        } catch (RuntimeException ignored) { /* Burp may be unloading. */ }
    }

    private void logFailure(String message, Exception error) {
        try {
            if (api != null && api.logging() != null) api.logging().logToError(message, error);
        } catch (RuntimeException ignored) { /* Burp may be unloading. */ }
    }
}
