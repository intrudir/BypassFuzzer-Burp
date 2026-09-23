package com.bypassfuzzer.burp.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.config.FuzzerConfig;
import com.bypassfuzzer.burp.core.attacks.*;
import com.bypassfuzzer.burp.core.collaborator.CollaboratorSupport;
import com.bypassfuzzer.burp.core.throttle.HostThrottleCoordinator;
import com.bypassfuzzer.burp.core.throttle.GlobalTrafficGovernor;
import com.bypassfuzzer.burp.core.throttle.RetryQueue;
import com.bypassfuzzer.burp.http.MontoyaRequestSender;
import com.bypassfuzzer.burp.http.ConfiguredHeaderPolicy;
import com.bypassfuzzer.burp.http.RequestSender;
import com.bypassfuzzer.core.scan.AttackFamily;
import com.bypassfuzzer.core.scan.BypassPlanner;
import com.bypassfuzzer.core.scan.PlannedRequest;

import java.util.List;
import java.util.function.Consumer;
import java.util.Set;
import java.util.LinkedHashSet;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Main fuzzer engine that orchestrates all attack strategies.
 */
public class FuzzerEngine {

    private final MontoyaApi api;
    private final FuzzerConfig config;
    private volatile boolean running = false;
    private Thread fuzzerThread;
    private volatile HostThrottleCoordinator coordinator;
    private RetryQueue<ThrottledRequest> retryQueue;
    private final RequestSender requestSender;
    private volatile com.bypassfuzzer.burp.http.BurpScanAdapter scanAdapter;
    private final AtomicInteger plannedPayloads = new AtomicInteger();
    private final AtomicLong httpRequestsSent = new AtomicLong();
    private final AtomicLong resultsRecorded = new AtomicLong();

    public FuzzerEngine(MontoyaApi api, FuzzerConfig config) {
        this(api, config, new GlobalTrafficGovernor());
    }

    public FuzzerEngine(MontoyaApi api, FuzzerConfig config, GlobalTrafficGovernor globalGovernor) {
        this(api, config, globalGovernor, null);
    }

    FuzzerEngine(MontoyaApi api, FuzzerConfig config, GlobalTrafficGovernor globalGovernor,
                 RequestSender requestSender) {
        this.api = api;
        this.config = config;
        GlobalTrafficGovernor governor = globalGovernor == null ? new GlobalTrafficGovernor() : globalGovernor;
        this.requestSender = requestSender == null
            ? new MontoyaRequestSender(api, governor) : requestSender;
    }

    /**
     * Start fuzzing with the given request.
     *
     * @param request The HTTP request to fuzz
     * @param resultCallback Callback to handle each result as it comes in
     */
    public boolean startFuzzing(HttpRequest request, Consumer<AttackResult> resultCallback) {
        return startFuzzing(request, resultCallback, null);
    }

    public boolean startFuzzing(HttpRequest request, Consumer<AttackResult> resultCallback, Runnable completionCallback) {
        if (running) {
            safeLog("Fuzzer is already running!");
            return false;
        }

        // Wait for previous thread to finish if it exists
        if (fuzzerThread != null && fuzzerThread.isAlive()) {
            safeLog("Waiting for previous fuzzer thread to complete...");
            try {
                fuzzerThread.join(5000); // Wait up to 5 seconds
                if (fuzzerThread.isAlive()) {
                    safeLog("Previous thread still running, interrupting...");
                    fuzzerThread.interrupt();
                    fuzzerThread.join(2000); // Wait another 2 seconds
                }
            } catch (InterruptedException e) {
                safeLog("Interrupted while waiting for previous thread");
            }
        }

        plannedPayloads.set(0);
        httpRequestsSent.set(0);
        resultsRecorded.set(0);
        retryQueue = new RetryQueue<>();
        running = true;

        fuzzerThread = new Thread(() -> {
            try {
                executeFuzzing(request, resultCallback);
            } catch (Exception e) {
                safeLogError("Fuzzer error: " + e.getMessage());
            } finally {
                running = false;
                if (completionCallback != null) {
                    completionCallback.run();
                }
            }
        }, "bypassfuzzer-engine");

        fuzzerThread.setDaemon(true);
        fuzzerThread.start();
        return true;
    }

    /**
     * Stop the fuzzer.
     */
    public void stopFuzzing() {
        if (running && fuzzerThread != null) {
            running = false;
            if (scanAdapter != null) scanAdapter.stop();
            HostThrottleCoordinator currentCoordinator = coordinator;
            if (currentCoordinator != null) currentCoordinator.manualResume();
            fuzzerThread.interrupt();
            safeLog("Fuzzer stopped by user");
        }
    }

    /**
     * Check if fuzzer is currently running.
     */
    public boolean isRunning() {
        return running;
    }

    public void pause() {
        if (!running) return;
        if (scanAdapter != null) scanAdapter.pause();
        HostThrottleCoordinator currentCoordinator = coordinator;
        if (currentCoordinator != null) currentCoordinator.manualPause();
    }

    public void resume() {
        if (scanAdapter != null) scanAdapter.resume();
        HostThrottleCoordinator currentCoordinator = coordinator;
        if (currentCoordinator != null) currentCoordinator.manualResume();
    }

    public boolean isPaused() {
        return scanAdapter != null && scanAdapter.isPaused();
    }

    public FuzzerProgress progress() {
        RetryQueue<ThrottledRequest> currentQueue = retryQueue;
        com.bypassfuzzer.burp.http.BurpScanAdapter currentScan = scanAdapter;
        return new FuzzerProgress(
            plannedPayloads.get(),
            currentScan == null ? httpRequestsSent.get() : currentScan.requestsSent(),
            resultsRecorded.get(),
            currentQueue == null ? 0 : currentQueue.size(),
            currentQueue == null ? 0 : currentQueue.rejectedCount()
        );
    }

    /**
     * Cleanup and stop all fuzzing threads gracefully.
     * Called during extension unload.
     */
    public void cleanup() {
        running = false;
        if (scanAdapter != null) scanAdapter.stop();
        if (fuzzerThread != null && fuzzerThread.isAlive()) {
            fuzzerThread.interrupt();
            try {
                fuzzerThread.join(2000); // Wait up to 2 seconds for thread to finish
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private void executeFuzzing(HttpRequest request, Consumer<AttackResult> resultCallback) {
        coordinator = new HostThrottleCoordinator(config.throttleSettings(), api);
        ConfiguredHeaderPolicy headers = new ConfiguredHeaderPolicy(
            config.getRequestHeaders(), config.getUserAgentMode(), config.getUserAgentRandomizationSeed());
        Set<AttackFamily> enabled = new LinkedHashSet<>();
        for (AttackType type : config.getEnabledAttackTypes()) enabled.add(AttackFamily.parse(type.id()));
        BypassPlanner planner = new BypassPlanner(() -> {
            if (!config.isEnableCollaboratorPayloads() || !CollaboratorSupport.isAvailable(api)) return "";
            String payload = CollaboratorSupport.generatePayload(api);
            return payload == null ? "" : payload.replaceFirst("^https?://", "").replaceFirst("/.*$", "");
        });
        com.bypassfuzzer.core.scan.ScanOptions options = new com.bypassfuzzer.core.scan.ScanOptions(
            com.bypassfuzzer.core.http.HttpProtocol.AUTO, java.time.Duration.ofSeconds(15),
            config.getConcurrency(), config.getPerHostConcurrency(), config.getThrottleStatusCodes(),
            3, true, config.throttleSettings().posture() ==
                com.bypassfuzzer.burp.core.throttle.ThrottleSettings.Posture.CONSERVATIVE
                ? "conservative" : "ride-hard", config.throttleSettings().pauseMode().name().toLowerCase(),
            config.throttleSettings().fixedPauseMillis(), false);
        com.bypassfuzzer.burp.http.BurpScanAdapter current = new com.bypassfuzzer.burp.http.BurpScanAdapter(
            request, requestSender, options, coordinator, mutation -> headers.reconcileMutation(request, mutation));
        scanAdapter = current;
        try {
            current.run("bypass", base -> {
                List<PlannedRequest> planned = planner.plan(base, enabled,
                    config.isEnableFuzzExistingCookies(), Integer.MAX_VALUE);
                plannedPayloads.set(planned.size());
                return planned;
            }, result -> {
                if (!running) return;
                handleResult(result, resultCallback);
                if (result.getThrottleRetryAttempt() == 3
                    && config.getThrottleStatusCodes().contains(result.getStatusCode())) {
                    retryQueue.enqueue(new ThrottledRequest(result.getRequest(), result.getAttackType(),
                        result.getPayload(), result.getTargetLabel(), result.getPayloadFamily(),
                        result.getPayloadEncoding(), 3));
                }
            });
            httpRequestsSent.set(current.requestsSent());
        } catch (Exception error) {
            safeLogError("Bypass scan failed: " + error.getMessage());
        }
    }

    private void handleResult(AttackResult result, Consumer<AttackResult> resultCallback) {
        try {
            resultCallback.accept(result);
            resultsRecorded.incrementAndGet();
        } catch (Exception callbackEx) {
            safeLogError("Error sending result to UI callback: " + callbackEx.getMessage());
        }
    }

    /**
     * Safe logging that handles API being null during extension unload.
     */
    private void safeLog(String message) {
        try {
            if (api != null && api.logging() != null) {
                api.logging().logToOutput(message);
            }
        } catch (Exception e) {
            // API unavailable during unload, ignore
        }
    }

    /**
     * Safe error logging that handles API being null during extension unload.
     */
    private void safeLogError(String message) {
        try {
            if (api != null && api.logging() != null) {
                api.logging().logToError(message);
            }
        } catch (Exception e) {
            // API unavailable during unload, ignore
        }
    }

    private String formatEnabledAttackTypes() {
        return config.getEnabledAttackTypes().stream()
            .map(AttackType::displayName)
            .toList()
            .toString();
    }
}
