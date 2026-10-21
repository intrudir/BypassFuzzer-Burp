package com.bypassfuzzer.burp.core.throttle;
import com.bypassfuzzer.core.throttle.AdaptiveRateController;
import com.bypassfuzzer.core.throttle.ThrottleSettings;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.core.throttle.*;
import java.net.URI;
import java.util.function.Consumer;
import java.util.function.LongSupplier;

/** Montoya boundary; all pacing and circuit state lives in shared core. */
public final class HostThrottleCoordinator extends com.bypassfuzzer.core.throttle.HostThrottleCoordinator<HttpRequest, HttpResponse> {
    public HostThrottleCoordinator(ThrottleSettings settings, MontoyaApi api) {
        this(settings, loggerFor(api), System::nanoTime, System::currentTimeMillis, null);
    }
    HostThrottleCoordinator(ThrottleSettings settings, Consumer<String> logger,
        LongSupplier nanoTime, LongSupplier currentTimeMillis, AdaptiveRateController.Tuning tuning) {
        super(settings, HostThrottleCoordinator::hostKey, response -> response.statusCode(),
            response -> response.headerValue("Retry-After"), logger, nanoTime, currentTimeMillis, tuning);
    }
    public static String hostKey(HttpRequest request) {
        try {
            URI uri = URI.create(request.url());
            int port = uri.getPort() < 0 ? ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80) : uri.getPort();
            return (uri.getScheme() == null ? "http" : uri.getScheme().toLowerCase())
                + "://" + uri.getHost().toLowerCase() + ":" + port;
        } catch (Exception ignored) {
            try { return request.httpService().toString(); }
            catch (Exception ignoredAgain) { return "unknown-host"; }
        }
    }
    private static Consumer<String> loggerFor(MontoyaApi api) {
        return message -> { try { if (api != null && api.logging() != null) api.logging().logToOutput(message); }
            catch (Exception ignored) { } };
    }
}
