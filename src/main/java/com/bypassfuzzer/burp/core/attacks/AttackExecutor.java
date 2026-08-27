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
     * Enable automatic re-queuing of throttled responses. When set, a response whose status is a
     * throttle code is added to the queue and its result callback is suppressed (the payload did not
     * land), for the caller to drain and retry later. When {@code null}, throttled responses are
     * delivered as ordinary results.
     */
    public void enableRetryQueue(RetryQueue<ThrottledRequest> retryQueue) {
        this.retryQueue = retryQueue;
    }

    public void enablePauseController(ExecutionPauseController pauseController) {
        this.pauseController = pauseController;
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
            coordinator, null);
    }

    public boolean execute(String attackType, String payload, HttpRequest request,
                           Consumer<AttackResult> resultCallback,
                           BooleanSupplier shouldContinue,
                           HostThrottleCoordinator coordinator,
                           HttpMode httpMode) {
        return executeInternal(attackType, payload, null, null, null, request, resultCallback, shouldContinue,
            coordinator, httpMode);
    }

    public boolean execute(String attackType, String payload, String targetLabel, String payloadFamily,
                           String payloadEncoding, HttpRequest request,
                           Consumer<AttackResult> resultCallback,
                           BooleanSupplier shouldContinue,
                           HostThrottleCoordinator coordinator) {
        return executeInternal(attackType, payload, targetLabel, payloadFamily, payloadEncoding, request,
            resultCallback, shouldContinue, coordinator, null);
    }

    public boolean execute(String attackType, String payload, String targetLabel, String payloadFamily,
                           String payloadEncoding, HttpRequest request,
                           Consumer<AttackResult> resultCallback,
                           BooleanSupplier shouldContinue,
                           HostThrottleCoordinator coordinator,
                           HttpMode httpMode) {
        return executeInternal(attackType, payload, targetLabel, payloadFamily, payloadEncoding, request,
            resultCallback, shouldContinue, coordinator, httpMode);
    }

    private boolean executeInternal(String attackType, String payload, String targetLabel, String payloadFamily,
                            String payloadEncoding, HttpRequest request,
                            Consumer<AttackResult> resultCallback,
                            BooleanSupplier shouldContinue,
                            HostThrottleCoordinator coordinator,
                            HttpMode httpMode) {
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
                    if (enqueueIfThrottled(coordinator, response, sentRequest, attackType, payload,
                            targetLabel, payloadFamily, payloadEncoding)) {
                        return;
                    }
                    resultCallback.accept(buildResult(attackType, payload, targetLabel, payloadFamily,
                        payloadEncoding, sentRequest, response));
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
        if (enqueueIfThrottled(coordinator, response, sentRequest, attackType, payload, targetLabel,
                payloadFamily, payloadEncoding)) {
            return true;
        }
        resultCallback.accept(buildResult(attackType, payload, targetLabel, payloadFamily,
            payloadEncoding, sentRequest, response));
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
        Supplier<HttpResponse> sender = () -> requestSender.send(
            sentRequest, timeout, timeUnit, () -> awaitResume(shouldContinue));
        HttpResponse response = coordinator == null
            ? (awaitResume(shouldContinue) ? sender.get() : null)
            : coordinator.send(sentRequest, sender, () -> awaitResume(shouldContinue));
        if (response == null) {
            return shouldContinue.getAsBoolean() && !Thread.currentThread().isInterrupted()
                ? AttackExecutionResult.timedOut()
                : AttackExecutionResult.stopped();
        }

        if (enqueueIfThrottled(coordinator, response, sentRequest, attackType, payload, null, null, null)) {
            return AttackExecutionResult.executed(response);
        }
        resultCallback.accept(new AttackResult(attackType, payload, sentRequest, response));
        return AttackExecutionResult.executed(response);
    }

    private HttpResponse sendPaced(HostThrottleCoordinator coordinator, HttpRequest request, HttpMode httpMode,
                                   BooleanSupplier shouldContinue) {
        Supplier<HttpResponse> networkSend = httpMode == null
            ? () -> requestSender.send(request, () -> awaitResume(shouldContinue))
            : () -> requestSender.send(request, httpMode, () -> awaitResume(shouldContinue));
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
     * retry and suppress the result callback (the payload did not land).
     *
     * @return true when the request was throttled and queued (caller should NOT deliver a result)
     */
    private boolean enqueueIfThrottled(HostThrottleCoordinator coordinator, HttpResponse response,
                                       HttpRequest sentRequest, String attackType, String payload,
                                       String targetLabel, String payloadFamily, String payloadEncoding) {
        if (retryQueue == null || coordinator == null || response == null) {
            return false;
        }
        if (coordinator.isThrottleStatusCode(response.statusCode())) {
            retryQueue.enqueue(new ThrottledRequest(sentRequest, attackType, payload,
                targetLabel == null ? "" : targetLabel,
                payloadFamily == null ? "" : payloadFamily,
                payloadEncoding == null ? "" : payloadEncoding,
                0));
            return true;
        }
        return false;
    }

    private static AttackResult buildResult(String attackType, String payload, String targetLabel,
                                            String payloadFamily, String payloadEncoding,
                                            HttpRequest request, HttpResponse response) {
        if (targetLabel == null && payloadFamily == null && payloadEncoding == null) {
            return new AttackResult(attackType, payload, request, response);
        }
        return new AttackResult(attackType, payload, targetLabel, payloadFamily, payloadEncoding,
            request, response);
    }
}
