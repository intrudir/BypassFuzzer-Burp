package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.ThrottledRequest;
import com.bypassfuzzer.burp.core.ExecutionPauseController;
import com.bypassfuzzer.burp.core.throttle.HostThrottleCoordinator;
import com.bypassfuzzer.burp.core.throttle.RetryQueue;
import com.bypassfuzzer.burp.http.RequestSender;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;

/**
 * Executes a prepared request using shared attack-loop semantics.
 * <p>Pacing and per-host adaptive throttling are delegated to a {@link HostThrottleCoordinator}: the
 * actual HTTP round-trip is wrapped in {@link HostThrottleCoordinator#send} so admission, sending,
 * and response reporting happen as one unit. When a concurrent send pool is configured via
 * {@link #enableConcurrentSends}, that unit is submitted to the pool so many requests are in flight
 * at once while the coordinator controls each host's rate.</p>
 */
public class AttackExecutor {

    private final RequestSender requestSender;
    private final UnaryOperator<HttpRequest> requestTransformer;
    private volatile ExecutorService sendPool;
    private volatile Semaphore inFlightPermits;
    private volatile int maxInFlight;
    private volatile RetryQueue<ThrottledRequest> retryQueue;
    private volatile ExecutionPauseController pauseController;
    private volatile Runnable requestAttemptListener = () -> { };

    public AttackExecutor(RequestSender requestSender) {
        this(requestSender, UnaryOperator.identity());
    }

    public AttackExecutor(RequestSender requestSender, UnaryOperator<HttpRequest> requestTransformer) {
        this.requestSender = requestSender;
        this.requestTransformer = requestTransformer == null ? UnaryOperator.identity() : requestTransformer;
    }

    /**
     * Enable concurrent HTTP sends. When set, {@code execute()} submits the paced round-trip to the
     * provided pool instead of blocking the caller. A semaphore bounds the number in flight.
     */
    public void enableConcurrentSends(ExecutorService pool, int maxInFlight) {
        this.sendPool = pool;
        this.maxInFlight = maxInFlight;
        this.inFlightPermits = new Semaphore(maxInFlight, true);
    }

    /**
     * Enable automatic re-queuing of throttled responses. Every attempt is still delivered to the
     * result callback as audit evidence; the caller can drain this queue for automatic replay while
     * the shared UI queue retains any request that never reaches a non-throttle outcome.
     */
    public void enableRetryQueue(RetryQueue<ThrottledRequest> retryQueue) {
        this.retryQueue = retryQueue;
    }

    public void enablePauseController(ExecutionPauseController pauseController) {
        this.pauseController = pauseController;
    }

    /** Called at the network boundary for every initial or retry HTTP attempt. */
    public void setRequestAttemptListener(Runnable listener) {
        this.requestAttemptListener = listener == null ? () -> { } : listener;
    }

    /** Wait for all in-flight concurrent sends to complete. */
    public void awaitInFlight() {
        Semaphore permits = this.inFlightPermits;
        if (permits == null) {
            return;
        }
        try {
            permits.acquire(maxInFlight);
            permits.release(maxInFlight);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public boolean execute(String attackType, String payload, HttpRequest request,
                           Consumer<AttackResult> resultCallback,
                           BooleanSupplier shouldContinue,
                           HostThrottleCoordinator coordinator) {
        return executeInternal(attackType, payload, null, null, null, request, resultCallback, shouldContinue,
            coordinator, null, 0);
    }

    public boolean execute(String attackType, String payload, HttpRequest request,
                           Consumer<AttackResult> resultCallback,
                           BooleanSupplier shouldContinue,
                           HostThrottleCoordinator coordinator,
                           HttpMode httpMode) {
        return executeInternal(attackType, payload, null, null, null, request, resultCallback, shouldContinue,
            coordinator, httpMode, 0);
    }

    public boolean execute(String attackType, String payload, String targetLabel, String payloadFamily,
                           String payloadEncoding, HttpRequest request,
                           Consumer<AttackResult> resultCallback,
                           BooleanSupplier shouldContinue,
                           HostThrottleCoordinator coordinator) {
        return executeInternal(attackType, payload, targetLabel, payloadFamily, payloadEncoding, request,
            resultCallback, shouldContinue, coordinator, null, 0);
    }

    public boolean execute(String attackType, String payload, String targetLabel, String payloadFamily,
                           String payloadEncoding, HttpRequest request,
                           Consumer<AttackResult> resultCallback,
                           BooleanSupplier shouldContinue,
                           HostThrottleCoordinator coordinator,
                           HttpMode httpMode) {
        return executeInternal(attackType, payload, targetLabel, payloadFamily, payloadEncoding, request,
            resultCallback, shouldContinue, coordinator, httpMode, 0);
    }

    /** Replays one throttled request while preserving its audit identity and retry attempt number. */
    public boolean executeRetry(ThrottledRequest retry,
                                Consumer<AttackResult> resultCallback,
                                BooleanSupplier shouldContinue,
                                HostThrottleCoordinator coordinator) {
        if (retry == null) return false;
        return executeInternal(
            retry.attackType(), retry.payload(), retry.targetLabel(), retry.payloadFamily(),
            retry.payloadEncoding(), retry.request(), resultCallback, shouldContinue, coordinator,
            null, retry.retryCount() + 1);
    }

    private boolean executeInternal(String attackType, String payload, String targetLabel, String payloadFamily,
                            String payloadEncoding, HttpRequest request,
                            Consumer<AttackResult> resultCallback,
                            BooleanSupplier shouldContinue,
                            HostThrottleCoordinator coordinator,
                            HttpMode httpMode,
                            int throttleRetryAttempt) {
        if (!AttackExecutionSupport.canContinue(shouldContinue)) {
            return false;
        }

        HttpRequest sentRequest = requestTransformer.apply(request);

        if (sendPool != null && inFlightPermits != null) {
            try {
                inFlightPermits.acquire();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
            sendPool.submit(() -> {
                try {
                    if (!awaitResume(shouldContinue)) {
                        return;
                    }
                    HttpResponse response = sendPaced(coordinator, sentRequest, httpMode, shouldContinue);
                    AttackResult result = buildResult(attackType, payload, targetLabel, payloadFamily,
                        payloadEncoding, sentRequest, response, throttleRetryAttempt);
                    enqueueIfThrottled(coordinator, result);
                    resultCallback.accept(result);
                } finally {
                    inFlightPermits.release();
                }
            });
            return true;
        }

        if (!awaitResume(shouldContinue)) {
            return false;
        }
        HttpResponse response = sendPaced(coordinator, sentRequest, httpMode, shouldContinue);
        AttackResult result = buildResult(attackType, payload, targetLabel, payloadFamily,
            payloadEncoding, sentRequest, response, throttleRetryAttempt);
        enqueueIfThrottled(coordinator, result);
        resultCallback.accept(result);
        return true;
    }

    public AttackExecutionResult executeWithTimeout(String attackType, String payload, HttpRequest request,
                                                    Consumer<AttackResult> resultCallback,
                                                    BooleanSupplier shouldContinue,
                                                    HostThrottleCoordinator coordinator,
                                                    long timeout,
                                                    TimeUnit timeUnit) {
        if (!AttackExecutionSupport.canContinue(shouldContinue)) {
            return AttackExecutionResult.stopped();
        }

        HttpRequest sentRequest = requestTransformer.apply(request);
        if (!awaitResume(shouldContinue)) {
            return AttackExecutionResult.stopped();
        }
        Supplier<HttpResponse> sender = () -> {
            requestAttemptListener.run();
            return requestSender.send(sentRequest, timeout, timeUnit, () -> awaitResume(shouldContinue));
        };
        HttpResponse response = coordinator == null
            ? (awaitResume(shouldContinue) ? sender.get() : null)
            : coordinator.send(sentRequest, sender, () -> awaitResume(shouldContinue));
        if (response == null) {
            return shouldContinue.getAsBoolean() && !Thread.currentThread().isInterrupted()
                ? AttackExecutionResult.timedOut()
                : AttackExecutionResult.stopped();
        }

        AttackResult result = new AttackResult(attackType, payload, sentRequest, response);
        enqueueIfThrottled(coordinator, result);
        resultCallback.accept(result);
        return AttackExecutionResult.executed(response);
    }

    private HttpResponse sendPaced(HostThrottleCoordinator coordinator, HttpRequest request, HttpMode httpMode,
                                   BooleanSupplier shouldContinue) {
        Supplier<HttpResponse> networkSend = httpMode == null
            ? () -> {
                requestAttemptListener.run();
                return requestSender.send(request, () -> awaitResume(shouldContinue));
            }
            : () -> {
                requestAttemptListener.run();
                return requestSender.send(request, httpMode, () -> awaitResume(shouldContinue));
            };
        // Recheck at the actual network boundary. A worker may have passed the first pause gate and
        // then waited in the throttle coordinator for pacing, a cooldown, or an in-flight permit.
        return coordinator == null
            ? (awaitResume(shouldContinue) ? networkSend.get() : null)
            : coordinator.send(request, networkSend, () -> awaitResume(shouldContinue));
    }

    private boolean awaitResume(BooleanSupplier shouldContinue) {
        ExecutionPauseController controller = pauseController;
        return controller == null || controller.awaitIfPaused(shouldContinue);
    }

    /**
     * If a retry queue is configured and the response is a throttle code, enqueue the request for
     * automatic replay. The HTTP result is always delivered separately so the table and shared
     * retry queue retain a complete audit trail even when automatic scheduling is at capacity.
     */
    private void enqueueIfThrottled(HostThrottleCoordinator coordinator, AttackResult result) {
        if (retryQueue == null || coordinator == null || result == null || result.getResponse() == null) {
            return;
        }
        if (coordinator.isThrottleStatusCode(result.getResponse().statusCode())) {
            retryQueue.enqueue(new ThrottledRequest(
                result.getRequest(), result.getAttackType(), result.getPayload(),
                result.getTargetLabel(), result.getPayloadFamily(), result.getPayloadEncoding(),
                result.getThrottleRetryAttempt()));
        }
    }

    private static AttackResult buildResult(String attackType, String payload, String targetLabel,
                                            String payloadFamily, String payloadEncoding,
                                            HttpRequest request, HttpResponse response,
                                            int throttleRetryAttempt) {
        AttackResult result;
        if (targetLabel == null && payloadFamily == null && payloadEncoding == null) {
            result = new AttackResult(attackType, payload, request, response);
        } else {
            result = new AttackResult(attackType, payload, targetLabel, payloadFamily, payloadEncoding,
                request, response);
        }
        return throttleRetryAttempt <= 0
            ? result : AttackResult.throttleRetryOf(result, response, throttleRetryAttempt);
    }
}
