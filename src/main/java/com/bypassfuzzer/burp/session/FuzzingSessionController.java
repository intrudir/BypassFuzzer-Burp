package com.bypassfuzzer.burp.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.config.FuzzerConfig;
import com.bypassfuzzer.burp.core.FuzzerEngine;
import com.bypassfuzzer.burp.core.FuzzerProgress;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.throttle.GlobalTrafficGovernor;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Owns the lifecycle of a single fuzzing session.
 */
public class FuzzingSessionController {

    private final String sessionId;
    private final HttpRequest request;
    private final FuzzerConfig config;
    private final FuzzerEngine engine;
    private final GlobalTrafficGovernor globalGovernor;
    private final List<Consumer<AttackResult>> resultListeners = new CopyOnWriteArrayList<>();
    private final List<Consumer<SessionState>> stateListeners = new CopyOnWriteArrayList<>();
    private final AtomicBoolean disposed = new AtomicBoolean(false);

    private volatile SessionState state = SessionState.IDLE;
    private volatile boolean stopRequested = false;

    public FuzzingSessionController(MontoyaApi api, HttpRequest request) {
        this(api, request, new GlobalTrafficGovernor());
    }

    public FuzzingSessionController(MontoyaApi api, HttpRequest request,
                                    GlobalTrafficGovernor globalGovernor) {
        this.sessionId = UUID.randomUUID().toString();
        this.request = request;
        this.config = new FuzzerConfig();
        this.globalGovernor = globalGovernor == null ? new GlobalTrafficGovernor() : globalGovernor;
        this.engine = new FuzzerEngine(api, this.config, this.globalGovernor);
    }

    FuzzingSessionController(HttpRequest request, FuzzerConfig config, FuzzerEngine engine) {
        this.sessionId = UUID.randomUUID().toString();
        this.request = request;
        this.config = config;
        this.engine = engine;
        this.globalGovernor = new GlobalTrafficGovernor();
    }

    public String sessionId() {
        return sessionId;
    }

    public HttpRequest request() {
        return request;
    }

    public FuzzerConfig config() {
        return config;
    }

    public GlobalTrafficGovernor globalGovernor() {
        return globalGovernor;
    }

    public SessionState state() {
        return state;
    }

    public boolean isRunning() {
        return engine.isRunning();
    }

    public void addResultListener(Consumer<AttackResult> listener) {
        resultListeners.add(listener);
    }

    public void addStateListener(Consumer<SessionState> listener) {
        stateListeners.add(listener);
    }

    public boolean start() {
        if (disposed.get()) {
            return false;
        }

        stopRequested = false;
        boolean started = engine.startFuzzing(request, this::publishResult, this::handleCompletion);
        if (started) {
            updateState(SessionState.RUNNING);
        }
        return started;
    }

    public void stop() {
        if (disposed.get()) {
            return;
        }

        stopRequested = true;
        engine.stopFuzzing();
    }

    public void pause() { engine.pause(); }
    public void resume() { engine.resume(); }
    public boolean isPaused() { return engine.isPaused(); }

    public FuzzerProgress progress() { return engine.progress(); }

    public void dispose() {
        if (!disposed.compareAndSet(false, true)) {
            return;
        }

        stopRequested = true;
        engine.cleanup();
        updateState(SessionState.DISPOSED);
        resultListeners.clear();
        stateListeners.clear();
    }

    private void publishResult(AttackResult result) {
        if (disposed.get()) {
            return;
        }

        for (Consumer<AttackResult> listener : resultListeners) {
            listener.accept(result);
        }
    }

    private void handleCompletion() {
        if (disposed.get()) {
            return;
        }

        updateState(stopRequested ? SessionState.STOPPED : SessionState.COMPLETED);
    }

    private void updateState(SessionState newState) {
        state = newState;
        for (Consumer<SessionState> listener : stateListeners) {
            listener.accept(newState);
        }
    }
}
