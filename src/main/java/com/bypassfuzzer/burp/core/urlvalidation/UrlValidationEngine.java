package com.bypassfuzzer.burp.core.urlvalidation;
import com.bypassfuzzer.core.scan.ScanDefaults;
import com.bypassfuzzer.core.scan.*;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.collaborator.CollaboratorSupport;
import com.bypassfuzzer.burp.core.throttle.GlobalTrafficGovernor;
import com.bypassfuzzer.burp.core.throttle.HostThrottleCoordinator;
import com.bypassfuzzer.burp.http.BurpScanAdapter;
import com.bypassfuzzer.burp.http.ConfiguredHeaderPolicy;
import com.bypassfuzzer.burp.http.MontoyaRequestSender;
import com.bypassfuzzer.burp.http.RequestSender;
import com.bypassfuzzer.core.http.HttpProtocol;
import com.bypassfuzzer.core.scan.ScanOptions;
import com.bypassfuzzer.core.scan.UrlValidationPlanner;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/** Burp lifecycle and transport adapter for the shared URL Validation scan. */
public class UrlValidationEngine {
    private final MontoyaApi api;
    private final RequestSender requestSender;
    private volatile boolean running;
    private volatile LiveRun live;
    private Thread runnerThread;
    private volatile BurpScanAdapter scanAdapter;
    private volatile HostThrottleCoordinator coordinator;
    private final AtomicLong httpRequestsSent = new AtomicLong();

    public UrlValidationEngine(MontoyaApi api) { this(api, new GlobalTrafficGovernor()); }
    public UrlValidationEngine(MontoyaApi api, GlobalTrafficGovernor governor) { this(api, governor, null); }
    UrlValidationEngine(MontoyaApi api, GlobalTrafficGovernor governor, RequestSender sender) {
        this.api = api;
        this.requestSender = sender == null ? new MontoyaRequestSender(api,
            governor == null ? new GlobalTrafficGovernor() : governor) : sender;
    }

    public boolean start(HttpRequest request, UrlValidationOptions options,
                         Consumer<AttackResult> resultCallback, Runnable completionCallback) {
        if (running) return false;
        httpRequestsSent.set(0);
        var initial=UrlValidationPayloadGenerator.toCoreOptions(options,"placeholder.invalid");
        live=new LiveRun(new RunConfiguration(java.util.Set.of(),options.concurrency(),Math.min(options.concurrency(),options.perHostConcurrency()),400,
            RunPlans.urlSelection(initial),options.requestHeaders(),java.util.Set.of(),options.userAgentMode(),options.userAgentRandomizationSeed()),RunPlans.url());
        live.registerHost(request.httpService().host());
        live.validateUsing(c -> {if(!c.excludes(request.httpService().host()))new UrlValidationPlanner().validate(c.prepare(new com.bypassfuzzer.burp.http.CoreRequestAdapter().fromMontoya(request),com.bypassfuzzer.core.http.RequestAccess.CORE),initial);});
        running = true;
        runnerThread = new Thread(() -> {
            try { execute(request, options, resultCallback); }
            finally {
                running = false;
                if (completionCallback != null) completionCallback.run();
            }
        }, "bypassfuzzer-url-validation");
        runnerThread.setDaemon(true);
        runnerThread.start();
        return true;
    }

    public void stop() { if(live!=null)live.stop();
        running = false;
        BurpScanAdapter current = scanAdapter;
        if (current != null) current.stop();
        HostThrottleCoordinator throttle = coordinator;
        if (throttle != null) throttle.manualResume();
        if (runnerThread != null) runnerThread.interrupt();
    }
    public void cleanup() {
        stop();
        if (runnerThread != null && runnerThread.isAlive()) {
            try { runnerThread.join(2000); }
            catch (InterruptedException error) { Thread.currentThread().interrupt(); }
        }
    }
    public boolean isRunning() { return running; }
    public void pause() {
        if (!running) return;
        if(live!=null){live.pause();return;}
        BurpScanAdapter current = scanAdapter;
        if (current != null) current.pause();
        HostThrottleCoordinator throttle = coordinator;
        if (throttle != null) throttle.manualPause();
    }
    public LiveRun liveRun(){return live;}
    public void resume() {
        if(live!=null){live.resume();return;}
        HostThrottleCoordinator throttle = coordinator;
        if (throttle != null) throttle.manualResume();
        BurpScanAdapter current = scanAdapter;
        if (current != null) current.resume();
    }
    public boolean isPaused() { return live!=null ? live.snapshot().state()==LiveRun.State.PAUSED || live.snapshot().state()==LiveRun.State.PAUSING : scanAdapter != null && scanAdapter.isPaused(); }
    public long httpRequestsSent() {
        BurpScanAdapter current = scanAdapter;
        return current == null ? httpRequestsSent.get() : current.requestsSent();
    }

    private void execute(HttpRequest request, UrlValidationOptions options,
                         Consumer<AttackResult> resultCallback) {
        try {
            String attackerHost = options.useCollaboratorPayloads()
                ? CollaboratorSupport.generatePayload(api) : options.normalizedAttackerHost();
            if (attackerHost == null || attackerHost.isBlank())
                throw new IllegalArgumentException("An attacker host is required");
            com.bypassfuzzer.core.urlvalidation.UrlValidationOptions coreOptions =
                UrlValidationPayloadGenerator.toCoreOptions(options, attackerHost);
            coordinator = new HostThrottleCoordinator(options.throttleSettings(), api);
            ConfiguredHeaderPolicy headers = new ConfiguredHeaderPolicy(options.requestHeaders(),
                options.userAgentMode(), options.userAgentRandomizationSeed());
            ScanOptions scanOptions = new ScanOptions(HttpProtocol.AUTO, Duration.ofSeconds(15),
                options.concurrency(), options.perHostConcurrency(), options.throttleStatusCodes(),
                ScanDefaults.URL_VALIDATION_RETRIES, false, options.posture().name().toLowerCase(),
                options.pauseMode().name().toLowerCase(), options.fixedPauseMillis(), false);
            BurpScanAdapter current = new BurpScanAdapter(request, requestSender, scanOptions,
                coordinator,mutated -> headers.reconcileMutation(request,mutated),live);
            scanAdapter = current;
            current.run("url-validation", base -> RunPlans.urlPlan(live,base,coreOptions,Integer.MAX_VALUE), result -> { if (running) resultCallback.accept(result); });
            httpRequestsSent.set(current.requestsSent());
        } catch (Exception error) {
            if (api != null) api.logging().logToError("URL Validation failed: " + error.getMessage());
        } finally { scanAdapter = null; }
    }

}
