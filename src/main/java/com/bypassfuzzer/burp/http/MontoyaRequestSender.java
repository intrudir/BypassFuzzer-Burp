package com.bypassfuzzer.burp.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.throttle.GlobalTrafficGovernor;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;

public class MontoyaRequestSender implements RequestSender {

    private static final AtomicInteger TIMEOUT_THREAD_COUNTER = new AtomicInteger(1);
    private static final int SAFE_REQUEST_ATTEMPTS = 2;
    private static final long SAFE_REQUEST_RETRY_DELAY_MS = 150;
    private static final ExecutorService TIMEOUT_EXECUTOR = Executors.newCachedThreadPool(runnable -> {
        Thread thread = new Thread(runnable, "bypassfuzzer-timeout-" + TIMEOUT_THREAD_COUNTER.getAndIncrement());
        thread.setDaemon(true);
        return thread;
    });

    private final MontoyaApi api;
    private final ExecutorService timeoutExecutor;
    private final boolean retrySafeRequestsOverHttp1;
    private final GlobalTrafficGovernor globalGovernor;

    public MontoyaRequestSender(MontoyaApi api) {
        this(api, TIMEOUT_EXECUTOR, false, new GlobalTrafficGovernor());
    }

    public MontoyaRequestSender(MontoyaApi api, boolean retrySafeRequestsOverHttp1) {
        this(api, TIMEOUT_EXECUTOR, retrySafeRequestsOverHttp1, new GlobalTrafficGovernor());
    }

    public MontoyaRequestSender(MontoyaApi api, GlobalTrafficGovernor globalGovernor) {
        this(api, TIMEOUT_EXECUTOR, false, globalGovernor);
    }

    public MontoyaRequestSender(MontoyaApi api, GlobalTrafficGovernor globalGovernor,
                                boolean retrySafeRequestsOverHttp1) {
        this(api, TIMEOUT_EXECUTOR, retrySafeRequestsOverHttp1, globalGovernor);
    }

    MontoyaRequestSender(MontoyaApi api, ExecutorService timeoutExecutor) {
        this(api, timeoutExecutor, false, new GlobalTrafficGovernor());
    }

    MontoyaRequestSender(MontoyaApi api, ExecutorService timeoutExecutor, boolean retrySafeRequestsOverHttp1) {
        this(api, timeoutExecutor, retrySafeRequestsOverHttp1, new GlobalTrafficGovernor());
    }

    MontoyaRequestSender(MontoyaApi api, ExecutorService timeoutExecutor,
                         boolean retrySafeRequestsOverHttp1, GlobalTrafficGovernor globalGovernor) {
        this.api = api;
        this.timeoutExecutor = timeoutExecutor;
        this.retrySafeRequestsOverHttp1 = retrySafeRequestsOverHttp1;
        this.globalGovernor = globalGovernor == null ? new GlobalTrafficGovernor() : globalGovernor;
    }

    @Override
    public HttpResponse send(HttpRequest request) {
        return send(request, () -> true);
    }

    @Override
    public HttpResponse send(HttpRequest request, BooleanSupplier shouldContinue) {
        Exception automaticFailure = null;
        int automaticAttempts = retrySafeRequestsOverHttp1 && isSafeMethod(request)
            ? SAFE_REQUEST_ATTEMPTS : 1;
        for (int attempt = 0; attempt < automaticAttempts; attempt++) {
            if (!canContinue(shouldContinue)) return null;
            try {
                HttpResponse response = globalGovernor.execute(request,
                    () -> responseFrom(api.http().sendRequest(request)), shouldContinue);
                if (response != null) {
                    return response;
                }
            } catch (Exception e) {
                automaticFailure = e;
            }
            if (attempt + 1 < automaticAttempts && !pauseBeforeRetry()) {
                return null;
            }
        }

        if (retrySafeRequestsOverHttp1 && isSafeMethod(request)) {
            if (!canContinue(shouldContinue)) return null;
            try {
                HttpResponse response = globalGovernor.execute(request,
                    () -> responseFrom(api.http().sendRequest(request, HttpMode.HTTP_1)), shouldContinue);
                if (response != null) {
                    safeLog("Sweep request automatic mode returned no usable response; HTTP/1 retry succeeded: "
                        + requestLabel(request));
                    return response;
                }
            } catch (Exception ignored) {
                // Report the original transport failure below; the retry is best effort.
            }
        }

        if (automaticFailure != null) {
            safeLogError("Sweep request failed: " + requestLabel(request) + " - "
                + (automaticFailure.getMessage() == null
                    ? automaticFailure.getClass().getSimpleName() : automaticFailure.getMessage()));
        } else {
            safeLogError("Sweep request returned no response"
                + (retrySafeRequestsOverHttp1 && isSafeMethod(request) ? " after an HTTP/1 retry" : "")
                + ": " + requestLabel(request));
        }
        return null;
    }

    private boolean pauseBeforeRetry() {
        try {
            Thread.sleep(SAFE_REQUEST_RETRY_DELAY_MS);
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    @Override
    public HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit) {
        return send(request, timeout, timeUnit, () -> true);
    }

    @Override
    public HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit,
                             BooleanSupplier shouldContinue) {
        return sendWithTimeout(request, () -> api.http().sendRequest(request).response(),
            timeout, timeUnit, shouldContinue);
    }

    @Override
    public HttpResponse send(HttpRequest request, HttpMode httpMode, long timeout, TimeUnit timeUnit) {
        return send(request, httpMode, timeout, timeUnit, () -> true);
    }

    @Override
    public HttpResponse send(HttpRequest request, HttpMode httpMode, long timeout, TimeUnit timeUnit,
                             BooleanSupplier shouldContinue) {
        return sendWithTimeout(request, () -> api.http().sendRequest(request, httpMode).response(),
            timeout, timeUnit, shouldContinue);
    }

    private HttpResponse sendWithTimeout(HttpRequest request,
                                         java.util.function.Supplier<HttpResponse> requestCall,
                                         long timeout, TimeUnit timeUnit,
                                         BooleanSupplier shouldContinue) {
        Future<HttpResponse> future = null;

        try {
            future = timeoutExecutor.submit(
                () -> globalGovernor.execute(request, requestCall, shouldContinue));
            HttpResponse response = future.get(timeout, timeUnit);
            if (response == null) safeLogError("Timed HTTP request returned no response.");
            return response;
        } catch (TimeoutException e) {
            if (future != null) {
                future.cancel(true);
            }
            safeLogError("Timed HTTP request exceeded " + timeout + " " + timeUnit.toString().toLowerCase() + ".");
            return null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        } catch (ExecutionException e) {
            Throwable cause = e.getCause() == null ? e : e.getCause();
            safeLogError("Timed HTTP request failed: " + cause.getClass().getSimpleName(), cause);
            return null;
        } catch (Exception e) {
            safeLogError("Timed HTTP request failed: " + e.getClass().getSimpleName(), e);
            return null;
        }
    }

    @Override
    public HttpResponse send(HttpRequest request, HttpMode httpMode) {
        return send(request, httpMode, () -> true);
    }

    @Override
    public HttpResponse send(HttpRequest request, HttpMode httpMode, BooleanSupplier shouldContinue) {
        if (!canContinue(shouldContinue)) return null;
        try {
            HttpResponse response = globalGovernor.execute(request,
                () -> responseFrom(api.http().sendRequest(request, httpMode)), shouldContinue);
            if (response == null) {
                safeLogError("Request returned no response in " + httpMode + " mode: " + requestLabel(request));
            }
            return response;
        } catch (Exception e) {
            safeLogError("Request failed in " + httpMode + " mode: " + requestLabel(request) + " - "
                + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            return null;
        }
    }

    private boolean canContinue(BooleanSupplier shouldContinue) {
        return !Thread.currentThread().isInterrupted()
            && (shouldContinue == null || shouldContinue.getAsBoolean());
    }

    private HttpResponse responseFrom(HttpRequestResponse exchange) {
        return exchange == null ? null : exchange.response();
    }

    private boolean isSafeMethod(HttpRequest request) {
        if (request == null || request.method() == null) {
            return false;
        }
        return "GET".equalsIgnoreCase(request.method()) || "HEAD".equalsIgnoreCase(request.method());
    }

    private String requestLabel(HttpRequest request) {
        if (request == null) {
            return "<null request>";
        }
        try {
            return request.method() + " " + request.url();
        } catch (Exception e) {
            return String.valueOf(request);
        }
    }

    private void safeLog(String message) {
        try {
            api.logging().logToOutput(message);
        } catch (Exception ignored) {
        }
    }

    private void safeLogError(String message) {
        try {
            api.logging().logToError(message);
        } catch (Exception ignored) {
        }
    }

    private void safeLogError(String message, Throwable cause) {
        try {
            api.logging().logToError(message, cause);
        } catch (Exception ignored) {
        }
    }
}
