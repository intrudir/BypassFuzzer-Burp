package com.bypassfuzzer.burp.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.config.FuzzerConfig;
import com.bypassfuzzer.burp.core.attacks.*;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Main fuzzer engine that orchestrates all attack strategies.
 */
public class FuzzerEngine {

    private final MontoyaApi api;
    private final FuzzerConfig config;
    private volatile boolean running = false;
    private Thread fuzzerThread;
    private RateLimiter rateLimiter;

    public FuzzerEngine(MontoyaApi api, FuzzerConfig config) {
        this.api = api;
        this.config = config;
    }

    /**
     * Start fuzzing with the given request.
     *
     * @param request The HTTP request to fuzz
     * @param resultCallback Callback to handle each result as it comes in
     */
    public void startFuzzing(HttpRequest request, Consumer<AttackResult> resultCallback) {
        if (running) {
            safeLog("Fuzzer is already running!");
            return;
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

        running = true;

        fuzzerThread = new Thread(() -> {
            try {
                executeFuzzing(request, resultCallback);
            } catch (Exception e) {
                safeLogError("Fuzzer error: " + e.getMessage());
            } finally {
                running = false;
            }
        });

        fuzzerThread.start();
    }

    /**
     * Stop the fuzzer.
     */
    public void stopFuzzing() {
        if (running && fuzzerThread != null) {
            running = false;
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

    /**
     * Cleanup and stop all fuzzing threads gracefully.
     * Called during extension unload.
     */
    public void cleanup() {
        running = false;
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
        String targetUrl = request.url();

        // Handle case where url() might return null or just a path
        if (targetUrl == null || targetUrl.isEmpty()) {
            safeLog("Error: Unable to determine target URL from request");
            running = false;
            return;
        }

        // If targetUrl is just a path (e.g., "/"), reconstruct full URL from Host header
        if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
            String host = request.headerValue("Host");
            if (host != null && !host.isEmpty()) {
                // Determine protocol - assume HTTPS if port 443, otherwise HTTP
                String protocol = "http";
                if (host.contains(":443") || request.isInScope()) {
                    protocol = "https";
                }
                targetUrl = protocol + "://" + host + targetUrl;
                safeLog("Reconstructed full URL from Host header: " + targetUrl);
            } else {
                safeLog("Error: No Host header found and URL is not absolute");
                running = false;
                return;
            }
        }

        // Initialize rate limiter
        rateLimiter = new RateLimiter(
            api,
            config.getRequestsPerSecond(),
            config.getThrottleStatusCodes(),
            config.isEnableAutoThrottle()
        );

        safeLog("=== BypassFuzzer Started ===");
        safeLog("Target: " + targetUrl);
        safeLog("Attack types enabled: " + String.join(", ", config.getAttackTypes()));

        if (config.getRequestsPerSecond() > 0) {
            safeLog("Rate limit: " + config.getRequestsPerSecond() + " requests/second");
        } else {
            safeLog("Rate limit: unlimited");
        }

        if (config.isEnableAutoThrottle() && !config.getThrottleStatusCodes().isEmpty()) {
            safeLog("Auto-throttle enabled for status codes: " + config.getThrottleStatusCodes());
        }

        List<AttackStrategy> strategies = buildAttackStrategies(targetUrl);
        safeLog("Built " + strategies.size() + " attack strategies");

        for (AttackStrategy strategy : strategies) {
            if (!running) {
                safeLog("Fuzzer stopped during execution");
                break;
            }

            String attackTypeLower = strategy.getAttackType().toLowerCase();
            boolean enabled = config.getAttackTypes().contains(attackTypeLower);

            if (!enabled) {
                safeLog("Skipping " + strategy.getAttackType() + " (disabled in config)");
                continue;
            }

            safeLog("\n=== Executing " + strategy.getAttackType() + " Attack ===");

            try {
                // Pass callback and running check to strategy - results sent immediately as they're generated
                strategy.execute(api, request, targetUrl, result -> {
                    if (running) {
                        try {
                            resultCallback.accept(result);
                            // Report response to rate limiter for auto-throttling
                            if (rateLimiter != null) {
                                rateLimiter.reportResponse(result.getStatusCode());
                            }
                        } catch (Exception callbackEx) {
                            safeLogError("Error sending result to UI callback: " + callbackEx.getMessage());
                        }
                    }
                }, () -> running, rateLimiter);

            } catch (Exception e) {
                safeLogError("Error in " + strategy.getAttackType() + " attack: " + e.getMessage());
            }
        }

        safeLog("\n=== BypassFuzzer Completed ===");
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

    private List<AttackStrategy> buildAttackStrategies(String targetUrl) {
        List<AttackStrategy> strategies = new ArrayList<>();

        // Order matches Python implementation
        strategies.add(new HeaderAttack(targetUrl, config.getOobPayload(), config.isEnableCollaboratorPayloads()));
        strategies.add(new PathAttack(targetUrl));
        strategies.add(new VerbAttack());
        strategies.add(new ParamAttack());
        strategies.add(new TrailingDotAttack());
        strategies.add(new TrailingSlashAttack());
        strategies.add(new ProtocolAttack());
        strategies.add(new CaseAttack());

        return strategies;
    }
}
