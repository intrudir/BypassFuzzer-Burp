package com.bypassfuzzer.burp.core.urlvalidation;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.throttle.HostThrottleCoordinator;
import com.bypassfuzzer.burp.core.throttle.GlobalTrafficGovernor;
import com.bypassfuzzer.burp.core.ExecutionPauseController;
import com.bypassfuzzer.burp.core.attacks.AttackExecutor;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.http.MontoyaRequestSender;
import com.bypassfuzzer.burp.http.RequestSender;
import com.bypassfuzzer.burp.http.TargetUrlResolver;
import com.bypassfuzzer.burp.http.ConfiguredHeaderPolicy;

import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Threaded execution engine for the URL Validation tab.
 */
public class UrlValidationEngine {

    private final MontoyaApi api;
    private final TargetUrlResolver targetUrlResolver = new TargetUrlResolver();
    private volatile boolean running = false;
    private Thread runnerThread;
    private volatile HostThrottleCoordinator coordinator;
    private final ExecutionPauseController pauseController = new ExecutionPauseController();
    private final GlobalTrafficGovernor globalGovernor;
    private final RequestSender requestSender;
    private final UrlValidationCandidateFinder candidateFinder;
    private final AtomicLong httpRequestsSent = new AtomicLong();

    public UrlValidationEngine(MontoyaApi api) {
        this(api, new GlobalTrafficGovernor());
    }

    public UrlValidationEngine(MontoyaApi api, GlobalTrafficGovernor globalGovernor) {
        this(api, globalGovernor, null);
    }

    UrlValidationEngine(MontoyaApi api, GlobalTrafficGovernor globalGovernor,
                        RequestSender requestSender) {
        this(api, globalGovernor, requestSender, new UrlValidationCandidateFinder());
    }

    UrlValidationEngine(MontoyaApi api, GlobalTrafficGovernor globalGovernor,
                        RequestSender requestSender, UrlValidationCandidateFinder candidateFinder) {
        this.api = api;
        this.globalGovernor = globalGovernor == null ? new GlobalTrafficGovernor() : globalGovernor;
        this.requestSender = requestSender == null
            ? new MontoyaRequestSender(api, this.globalGovernor) : requestSender;
        this.candidateFinder = candidateFinder == null
            ? new UrlValidationCandidateFinder() : candidateFinder;
    }

    public boolean start(HttpRequest request, UrlValidationOptions options, Consumer<AttackResult> resultCallback, Runnable completionCallback) {
        if (running) {
            return false;
        }

        pauseController.reset();
        httpRequestsSent.set(0);
        running = true;
        runnerThread = new Thread(() -> {
            try {
                execute(request, options, resultCallback);
            } finally {
                running = false;
                if (completionCallback != null) {
                    completionCallback.run();
                }
            }
        }, "bypassfuzzer-url-validation");
        runnerThread.setDaemon(true);
        runnerThread.start();
        return true;
    }

    public void stop() {
        running = false;
        HostThrottleCoordinator currentCoordinator = coordinator;
        if (currentCoordinator != null) currentCoordinator.manualResume();
        pauseController.resume();
        if (runnerThread != null) {
            runnerThread.interrupt();
        }
    }

    public void cleanup() {
        stop();
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

    public void pause() {
        if (!running) return;
        pauseController.pause();
        HostThrottleCoordinator currentCoordinator = coordinator;
        if (currentCoordinator != null) currentCoordinator.manualPause();
    }

    public void resume() {
        HostThrottleCoordinator currentCoordinator = coordinator;
        if (currentCoordinator != null) currentCoordinator.manualResume();
        pauseController.resume();
    }
    public boolean isPaused() { return pauseController.isPaused(); }

    public long httpRequestsSent() { return httpRequestsSent.get(); }

    private void execute(HttpRequest request, UrlValidationOptions options, Consumer<AttackResult> resultCallback) {
        String targetUrl = targetUrlResolver.resolve(request);
        coordinator = new HostThrottleCoordinator(options.throttleSettings(), api);

        ConfiguredHeaderPolicy headerPolicy = new ConfiguredHeaderPolicy(
            options.requestHeaders(), options.userAgentMode(), options.userAgentRandomizationSeed());
        UrlValidationAttack attack = new UrlValidationAttack(
            options, candidateFinder, new UrlValidationPayloadGenerator());
        AttackExecutor attackExecutor = new AttackExecutor(
            requestSender,
            mutated -> headerPolicy.reconcileMutation(request, mutated));
        attackExecutor.enablePauseController(pauseController);
        attackExecutor.setRequestAttemptListener(httpRequestsSent::incrementAndGet);
        attack.execute(api, request, targetUrl, result -> {
            if (running) {
                resultCallback.accept(result);
            }
        }, () -> running, coordinator, attackExecutor);
    }
}
