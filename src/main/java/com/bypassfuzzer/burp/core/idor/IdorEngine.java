package com.bypassfuzzer.burp.core.idor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.throttle.HostThrottleCoordinator;
import com.bypassfuzzer.burp.core.throttle.GlobalTrafficGovernor;
import com.bypassfuzzer.burp.core.ExecutionPauseController;
import com.bypassfuzzer.burp.core.attacks.AttackExecutor;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.idor.playbooks.IdorPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.IdorPlaybookRegistry;
import com.bypassfuzzer.burp.core.idor.playbooks.IdorRequestVariant;
import com.bypassfuzzer.burp.http.MontoyaRequestSender;
import com.bypassfuzzer.burp.http.RequestSender;
import com.bypassfuzzer.burp.http.ConfiguredHeaderPolicy;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Threaded execution engine for IDOR/BOLA analysis.
 */
public class IdorEngine {

    private final MontoyaApi api;
    private final IdorRequestContextAnalyzer contextAnalyzer;
    private final IdorPlaybookRegistry playbookRegistry;
    private final RequestSender requestSender;

    private volatile boolean running = false;
    private Thread runnerThread;
    private volatile HostThrottleCoordinator coordinator;
    private final ExecutionPauseController pauseController = new ExecutionPauseController();

    public IdorEngine(MontoyaApi api) {
        this(api, new IdorRequestContextAnalyzer(), new IdorPlaybookRegistry(), new MontoyaRequestSender(api));
    }

    public IdorEngine(MontoyaApi api, GlobalTrafficGovernor globalGovernor) {
        this(api, new IdorRequestContextAnalyzer(), new IdorPlaybookRegistry(),
            new MontoyaRequestSender(api, globalGovernor));
    }

    IdorEngine(MontoyaApi api,
               IdorRequestContextAnalyzer contextAnalyzer,
               IdorPlaybookRegistry playbookRegistry,
               RequestSender requestSender) {
        this.api = api;
        this.contextAnalyzer = contextAnalyzer;
        this.playbookRegistry = playbookRegistry;
        this.requestSender = requestSender;
    }

    public boolean start(HttpRequest request, IdorOptions options, Consumer<AttackResult> resultCallback, Runnable completionCallback) {
        if (running) {
            return false;
        }

        pauseController.reset();
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
        }, "bypassfuzzer-idor");
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

    private void execute(HttpRequest request, IdorOptions options, Consumer<AttackResult> resultCallback) {
        if (request == null || options == null || options.runOptions() == null) {
            return;
        }

        String authorizedIdentifier = options.normalizedAuthorizedIdentifier();
        String targetIdentifier = options.normalizedTargetIdentifier();
        if (authorizedIdentifier.isEmpty() || targetIdentifier.isEmpty()) {
            return;
        }

        ConfiguredHeaderPolicy headerPolicy = new ConfiguredHeaderPolicy(
            options.runOptions().requestHeaders(), options.runOptions().userAgentMode(),
            options.runOptions().userAgentRandomizationSeed());
        IdorRequestContext context = contextAnalyzer.analyze(request, options);
        HttpRequest targetRequest = context.targetRequest();
        if (!running) {
            return;
        }

        coordinator = new HostThrottleCoordinator(options.runOptions().throttleSettings(), api);

        AttackExecutor attackExecutor = new AttackExecutor(
            requestSender, mutated -> headerPolicy.reconcileMutation(request, mutated));
        attackExecutor.enablePauseController(pauseController);
        Consumer<AttackResult> publishingCallback = result -> {
            if (!running) {
                return;
            }
            resultCallback.accept(result);
        };

        if (!attackExecutor.execute(
            "IDOR",
            "Control: authorized identifier 1 (" + authorizedIdentifier + ")",
            "Control",
            "idor.baseline.control",
            null,
            request,
            publishingCallback,
            () -> running,
            coordinator
        )) {
            return;
        }

        if (!attackExecutor.execute(
            "IDOR",
            "Baseline: identifier 2 without bypass (" + targetIdentifier + ")",
            "Baseline",
            "idor.baseline.target",
            null,
            targetRequest,
            publishingCallback,
            () -> running,
            coordinator
        )) {
            return;
        }

        // Deduplicate across playbooks: if two playbooks produce the same
        // effective request (same method + path + query + headers + body),
        // only send the first one. Prevents wasting requests when e.g.
        // IdentifierAliases and ParameterPollution both emit ?id[0]=carlos.
        Set<String> sentRequests = new HashSet<>();

        for (IdorPlaybook playbook : playbookRegistry.all()) {
            if (!running) {
                return;
            }

            List<IdorRequestVariant> variants = playbook.buildVariants(context);
            for (IdorRequestVariant variant : variants) {
                if (!running) {
                    return;
                }

                // Include headers so Accept, Content-Type, and method-override variants remain distinct.
                String dedupKey = variant.request().toString();
                if (!sentRequests.add(dedupKey)) {
                    continue;
                }

                if (!attackExecutor.execute(
                    "IDOR",
                    variant.label(),
                    playbook.displayName(),
                    playbook.id(),
                    null,
                    variant.request(),
                    publishingCallback,
                    () -> running,
                    coordinator
                )) {
                    return;
                }
            }
        }
    }
}
