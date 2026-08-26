package com.bypassfuzzer.burp.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.config.FuzzerConfig;
import com.bypassfuzzer.burp.core.attacks.*;
import com.bypassfuzzer.burp.core.throttle.HostThrottleCoordinator;
import com.bypassfuzzer.burp.core.throttle.GlobalTrafficGovernor;
import com.bypassfuzzer.burp.core.throttle.RetryQueue;
import com.bypassfuzzer.burp.http.MontoyaRequestSender;
import com.bypassfuzzer.burp.http.ConfiguredHeaderPolicy;
import com.bypassfuzzer.burp.http.TargetUrlResolver;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Consumer;

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
    private final TargetUrlResolver targetUrlResolver;
    private final AttackRegistry attackRegistry;
    private final ExecutionPauseController pauseController = new ExecutionPauseController();
    private final GlobalTrafficGovernor globalGovernor;

    public FuzzerEngine(MontoyaApi api, FuzzerConfig config) {
        this(api, config, new GlobalTrafficGovernor());
    }

    public FuzzerEngine(MontoyaApi api, FuzzerConfig config, GlobalTrafficGovernor globalGovernor) {
        this.api = api;
        this.config = config;
        this.globalGovernor = globalGovernor == null ? new GlobalTrafficGovernor() : globalGovernor;
        this.targetUrlResolver = new TargetUrlResolver();
        this.attackRegistry = new AttackRegistry();
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

        pauseController.reset();
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

        fuzzerThread.start();
        return true;
    }

    /**
     * Stop the fuzzer.
     */
    public void stopFuzzing() {
        if (running && fuzzerThread != null) {
            running = false;
            HostThrottleCoordinator currentCoordinator = coordinator;
            if (currentCoordinator != null) currentCoordinator.manualResume();
            pauseController.resume();
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
        pauseController.pause();
        HostThrottleCoordinator currentCoordinator = coordinator;
        if (currentCoordinator != null) currentCoordinator.manualPause();
    }

    public void resume() {
        HostThrottleCoordinator currentCoordinator = coordinator;
        if (currentCoordinator != null) currentCoordinator.manualResume();
        pauseController.resume();
    }

    public boolean isPaused() {
        return pauseController.isPaused();
    }

    /**
     * Cleanup and stop all fuzzing threads gracefully.
     * Called during extension unload.
     */
    public void cleanup() {
        running = false;
        pauseController.resume();
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
        final String targetUrl;
        try {
            targetUrl = targetUrlResolver.resolve(request);
        } catch (IllegalArgumentException e) {
            safeLog("Error: " + e.getMessage());
            return;
        }

        // Per-host adaptive rate control finds each host's ceiling and rides just under it.
        coordinator = new HostThrottleCoordinator(config.throttleSettings(), api);
        retryQueue = new RetryQueue<>();

        safeLog("=== BypassFuzzer Started ===");
        safeLog("Target: " + targetUrl);
        safeLog("Attack types enabled: " + formatEnabledAttackTypes());
        safeLog("Adaptive rate control: pacing each host just under its rate limit; throttle codes "
            + config.getThrottleStatusCodes());

        ConfiguredHeaderPolicy headerPolicy = new ConfiguredHeaderPolicy(
            config.getRequestHeaders(), config.getUserAgentMode(), config.getUserAgentRandomizationSeed());
        List<RegisteredAttack> attacks = attackRegistry.buildEnabledAttacks(config, targetUrl);
        AttackExecutor attackExecutor = new AttackExecutor(
            new MontoyaRequestSender(api, globalGovernor),
            mutated -> headerPolicy.reconcileMutation(request, mutated));
        safeLog("Built " + attacks.size() + " attack strategies");

        // Keep many requests in flight so the adaptive controller can drive each host at full speed;
        // throttled payloads are re-queued and retried so coverage stays complete.
        int maxInFlight = 50;
        ExecutorService sendPool = Executors.newFixedThreadPool(maxInFlight, runnable -> {
            Thread t = new Thread(runnable, "bypassfuzzer-send");
            t.setDaemon(true);
            return t;
        });
        attackExecutor.enableConcurrentSends(sendPool, maxInFlight);
        attackExecutor.enablePauseController(pauseController);
        attackExecutor.enableRetryQueue(retryQueue);

        int concurrency = Math.max(1, config.getConcurrency());
        if (concurrency > 1 && attacks.size() > 1) {
            executeAttacksConcurrently(request, targetUrl, resultCallback, attacks, attackExecutor, concurrency);
        } else {
            executeAttacksSequentially(request, targetUrl, resultCallback, attacks, attackExecutor);
        }

        // Wait for all in-flight concurrent sends to finish
        attackExecutor.awaitInFlight();

        // Retry any requests that were throttled, while the send pool is still alive.
        if (!retryQueue.isEmpty()) {
            drainRetryQueue(request, resultCallback, attackExecutor);
        }

        sendPool.shutdown();

        safeLog("\n=== BypassFuzzer Completed ===");
    }

    private void executeAttacksSequentially(HttpRequest request,
                                            String targetUrl,
                                            Consumer<AttackResult> resultCallback,
                                            List<RegisteredAttack> attacks,
                                            AttackExecutor attackExecutor) {
        for (RegisteredAttack attack : attacks) {
            if (!running) {
                safeLog("Fuzzer stopped during execution");
                break;
            }

            executeAttack(request, targetUrl, resultCallback, attack, attackExecutor);
        }
    }

    private void executeAttacksConcurrently(HttpRequest request,
                                            String targetUrl,
                                            Consumer<AttackResult> resultCallback,
                                            List<RegisteredAttack> attacks,
                                            AttackExecutor attackExecutor,
                                            int concurrency) {
        ExecutorService executor = Executors.newFixedThreadPool(Math.min(concurrency, attacks.size()), runnable -> {
            Thread thread = new Thread(runnable, "bypassfuzzer-attack-worker");
            thread.setDaemon(true);
            return thread;
        });
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (RegisteredAttack attack : attacks) {
                futures.add(executor.submit(() -> executeAttack(request, targetUrl, resultCallback, attack, attackExecutor)));
            }

            for (Future<?> future : futures) {
                if (!running) {
                    break;
                }
                try {
                    future.get();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    running = false;
                    break;
                } catch (Exception e) {
                    safeLogError("Concurrent attack worker error: " + e.getMessage());
                }
            }
        } finally {
            executor.shutdownNow();
        }
    }

    private void executeAttack(HttpRequest request,
                               String targetUrl,
                               Consumer<AttackResult> resultCallback,
                               RegisteredAttack attack,
                               AttackExecutor attackExecutor) {
        if (!running) {
            return;
        }

        safeLog("\n=== Executing " + attack.type().displayName() + " Attack ===");

        try {
            attack.strategy().execute(api, request, targetUrl, result -> {
                if (running) {
                    handleResult(result, resultCallback);
                }
            }, () -> running, coordinator, attackExecutor);
        } catch (Exception e) {
            safeLogError("Error in " + attack.type().displayName() + " attack: " + e.getMessage());
        }
    }

    private void drainRetryQueue(HttpRequest originalRequest, Consumer<AttackResult> resultCallback,
                                 AttackExecutor attackExecutor) {
        int maxPasses = 3;
        for (int pass = 1; pass <= maxPasses && running && !retryQueue.isEmpty(); pass++) {
            List<ThrottledRequest> retries = retryQueue.drain(Integer.MAX_VALUE);
            if (retries.isEmpty()) break;

            safeLog(String.format("Retrying %d throttled requests (pass %d)...", retries.size(), pass));
            for (ThrottledRequest retry : retries) {
                if (!running) break;
                attackExecutor.execute(
                    retry.attackType(), retry.payload(), retry.targetLabel(),
                    retry.payloadFamily(), retry.payloadEncoding(),
                    retry.request(),
                    result -> { if (running) handleResult(result, resultCallback); },
                    () -> running,
                    coordinator
                );
            }
            // Let this pass complete before deciding whether another is needed.
            attackExecutor.awaitInFlight();
        }
        int remaining = retryQueue.size();
        if (remaining > 0) {
            safeLog(String.format("Retry limit reached; %d throttled payloads remain.", remaining));
        }
    }

    private void handleResult(AttackResult result, Consumer<AttackResult> resultCallback) {
        try {
            resultCallback.accept(result);
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
