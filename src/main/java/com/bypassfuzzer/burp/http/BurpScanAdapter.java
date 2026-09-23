package com.bypassfuzzer.burp.http;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.throttle.HostThrottleCoordinator;
import com.bypassfuzzer.core.http.HttpHeader;
import com.bypassfuzzer.core.http.HttpRequestData;
import com.bypassfuzzer.core.http.HttpResponseData;
import com.bypassfuzzer.core.http.RequestTransport;
import com.bypassfuzzer.core.scan.ScanEngine;
import com.bypassfuzzer.core.scan.ScanEvent;
import com.bypassfuzzer.core.scan.ScanOptions;
import com.bypassfuzzer.core.scan.PlannedRequest;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.UnaryOperator;

/** Montoya transport and result conversion for the shared scan engine. */
public final class BurpScanAdapter {
    private final CoreRequestAdapter requests = new CoreRequestAdapter();
    private final HttpRequest original;
    private final RequestSender sender;
    private final HostThrottleCoordinator coordinator;
    private final UnaryOperator<HttpRequest> requestPolicy;
    private final ThreadLocal<Exchange> lastExchange = new ThreadLocal<>();
    private volatile Exchange authorizedControl;
    private volatile Exchange targetControl;
    private final ScanEngine engine;

    public BurpScanAdapter(HttpRequest original, RequestSender sender, ScanOptions options) {
        this(original, sender, options, null);
    }

    public BurpScanAdapter(HttpRequest original, RequestSender sender, ScanOptions options,
                           HostThrottleCoordinator coordinator) {
        this(original, sender, options, coordinator, value -> value);
    }

    public BurpScanAdapter(HttpRequest original, RequestSender sender, ScanOptions options,
                           HostThrottleCoordinator coordinator, UnaryOperator<HttpRequest> requestPolicy) {
        this.original = original;
        this.sender = sender;
        this.coordinator = coordinator;
        this.requestPolicy = requestPolicy;
        this.engine = new ScanEngine(options);
    }

    public ScanEngine.Summary run(String mode, Function<HttpRequestData, List<PlannedRequest>> planner,
                                  Consumer<AttackResult> results) throws Exception {
        return run(mode, planner, null, results);
    }

    public ScanEngine.Summary run(String mode, Function<HttpRequestData, List<PlannedRequest>> planner,
                                  ScanEngine.PostBaselinePlanner postBaselinePlanner,
                                  Consumer<AttackResult> results) throws Exception {
        RequestTransport transport = (request, timeout) -> {
            HttpRequest montoya = requestPolicy.apply(requests.toMontoya(original, request));
            java.util.function.Supplier<HttpResponse> send = () -> sender.send(montoya,
                requests.httpMode(request.protocol()), timeout.toMillis(), TimeUnit.MILLISECONDS);
            HttpResponse response = coordinator == null ? send.get()
                : coordinator.send(montoya, send);
            if (response == null) {
                lastExchange.set(new Exchange(montoya, null));
                return null;
            }
            byte[] body = response.body() == null ? new byte[0] : response.body().getBytes();
            List<HttpHeader> headers = response.headers().stream()
                .map(header -> new HttpHeader(header.name(), header.value())).toList();
            HttpResponseData converted = new HttpResponseData(request.protocol(), response.statusCode(),
                headers, body, 0);
            lastExchange.set(new Exchange(montoya, response));
            return converted;
        };
        return engine.run(mode, List.of(requests.fromMontoya(original)), planner,
            postBaselinePlanner, transport,
            event -> results.accept(toResult(event)));
    }

    public void pause() { engine.pause(); }
    public void resume() { engine.resume(); }
    public void stop() { engine.stop(); }
    public boolean isPaused() { return engine.isPaused(); }
    public long requestsSent() { return engine.requestsSent(); }

    private AttackResult toResult(ScanEvent event) {
        Exchange exchange = lastExchange.get();
        lastExchange.remove();
        HttpRequest request = exchange == null ? requests.toMontoya(original, event.planned().request()) : exchange.request();
        HttpResponse response = exchange == null ? null : exchange.response();
        boolean targetBaseline = event.planned().payload().equals("idor.baseline.target");
        Exchange originalEvidence = authorizedControl;
        Exchange targetEvidence = targetControl;
        if (event.planned().baseline()) {
            if (targetBaseline) targetControl = new Exchange(request, response);
            else authorizedControl = new Exchange(request, response);
        }
        String attackType = switch (event.mode()) {
            case "idor" -> "IDOR";
            case "url-validation" -> "URL Validation";
            case "sweep" -> "Coverage Sweep";
            default -> "Bypass";
        };
        AttackResult result = new AttackResult(attackType, event.planned().payload(),
            event.target(), event.planned().family(), event.signal(), request, response,
            originalEvidence == null ? null : originalEvidence.request(),
            originalEvidence == null ? null : originalEvidence.response(),
            targetEvidence == null ? null : targetEvidence.request(),
            targetEvidence == null ? null : targetEvidence.response());
        return event.retryAttempt() > 0 ? AttackResult.throttleRetryOf(result, response, event.retryAttempt()) : result;
    }

    private record Exchange(HttpRequest request, HttpResponse response) { }
}
