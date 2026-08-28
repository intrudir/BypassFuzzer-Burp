package com.bypassfuzzer.burp.core.throttle;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.net.URI;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * The single admission funnel every scan pipeline routes requests through. It keeps one
 * {@link AdaptiveRateController} per host (keyed by {@code scheme://host:port}) so each host's
 * rate-limit ceiling is discovered and ridden independently, and bounds in-flight concurrency with a
 * global safety semaphore plus a per-host semaphore.
 *
 * <p>Pacing is done entirely by the per-host controller's token bucket; the semaphores are only a
 * resource cap on how many requests may be outstanding at once, never the rate control.</p>
 */
public final class HostThrottleCoordinator {

    private static final int SMART_WINDOW_SIZE = 50;
    private static final int SMART_MIN_WINDOW_SIZE = 25;
    private static final int SMART_MIN_THROTTLES = 10;
    private static final double SMART_THROTTLE_RATIO = 0.40;
    private static final int SMART_THROTTLE_STREAK = 8;
    private static final int HALF_OPEN_SUCCESSES = 5;
    private static final long SMART_RESET_AFTER_MILLIS = 60_000L;

    private final ThrottleSettings settings;
    private final Consumer<String> logger;
    private final LongSupplier nanoTime;
    private final LongSupplier currentTimeMillis;
    private final AdaptiveRateController.Tuning tuningOverride;
    private final Semaphore globalPermits;
    private final AtomicInteger inFlightRequests = new AtomicInteger();
    private final Map<String, HostState> hosts = new ConcurrentHashMap<>();
    private final Object manualPauseLock = new Object();
    private volatile boolean manuallyPaused;
    private final Object globalPauseLock = new Object();
    private long globalPauseUntilMillis;
    private final SmartCircuit globalSmartCircuit = new SmartCircuit("Global CDN/WAF", true);

    public HostThrottleCoordinator(ThrottleSettings settings, MontoyaApi api) {
        this(settings, loggerFor(api), System::nanoTime, System::currentTimeMillis, null);
    }

    HostThrottleCoordinator(ThrottleSettings settings, Consumer<String> logger,
                            LongSupplier nanoTime, LongSupplier currentTimeMillis,
                            AdaptiveRateController.Tuning tuningOverride) {
        this.settings = settings == null ? ThrottleSettings.defaults() : settings;
        this.logger = logger;
        this.nanoTime = nanoTime;
        this.currentTimeMillis = currentTimeMillis;
        this.tuningOverride = tuningOverride;
        this.globalPermits = new Semaphore(this.settings.globalConcurrency(), true);
    }

    /**
     * Paces and sends one request through the supplied sender, feeding the response back into the
     * host's adaptive controller.
     *
     * @return the response, or {@code null} if the send failed or the thread was interrupted.
     */
    public HttpResponse send(HttpRequest request, Supplier<HttpResponse> sender) {
        return send(request, sender, () -> true);
    }

    /**
     * Sends after all throttle gates and a final caller-owned admission check. The latter lets scan
     * pause controls stop workers that were already queued inside this coordinator.
     */
    public HttpResponse send(HttpRequest request, Supplier<HttpResponse> sender,
                             BooleanSupplier finalAdmission) {
        HostState host = hosts.computeIfAbsent(hostKey(request), HostState::new);
        boolean globalAcquired = false;
        boolean hostAcquired = false;
        GateAdmission hostAdmission = GateAdmission.OPEN;
        GateAdmission globalAdmission = GateAdmission.OPEN;
        boolean outcomeReported = false;
        try {
            if (!awaitGlobalPause()
                || awaitSmartCircuit(globalSmartCircuit, false) == GateAdmission.INTERRUPTED) {
                return null;
            }
            globalPermits.acquire();
            globalAcquired = true;
            host.permits.acquire();
            hostAcquired = true;

            hostAdmission = awaitSmartCircuit(host.smartCircuit, true);
            if (hostAdmission == GateAdmission.INTERRUPTED) {
                return null;
            }
            globalAdmission = awaitGlobalAdmission();
            if (globalAdmission == GateAdmission.INTERRUPTED) {
                return null;
            }

            if (finalAdmission != null && !finalAdmission.getAsBoolean()) {
                return null;
            }
            long generation = host.controller.acquire();
            if (generation < 0) {
                return null;
            }
            if (finalAdmission != null && !finalAdmission.getAsBoolean()) {
                return null;
            }
            HttpResponse response;
            inFlightRequests.incrementAndGet();
            try {
                response = sender.get();
            } finally {
                inFlightRequests.decrementAndGet();
            }
            if (response != null) {
                host.controller.report(response.statusCode(), retryAfter(response), generation);
                reportPauseOutcome(host, response, hostAdmission, globalAdmission);
                outcomeReported = true;
            }
            return response;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        } finally {
            if (!outcomeReported) {
                cancelHalfOpenProbe(host.smartCircuit, hostAdmission);
                cancelHalfOpenProbe(globalSmartCircuit, globalAdmission);
            }
            if (hostAcquired) {
                host.permits.release();
            }
            if (globalAcquired) {
                globalPermits.release();
            }
        }
    }

    private boolean awaitGlobalPause() {
        synchronized (globalPauseLock) {
            while (true) {
                long remaining = globalPauseUntilMillis - currentTimeMillis.getAsLong();
                if (remaining <= 0) {
                    return true;
                }
                try {
                    globalPauseLock.wait(Math.min(remaining, 1_000L));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
        }
    }

    private GateAdmission awaitGlobalAdmission() {
        if (!awaitGlobalPause()) {
            return GateAdmission.INTERRUPTED;
        }
        return awaitSmartCircuit(globalSmartCircuit, true);
    }

    private void reportPauseOutcome(HostState host, HttpResponse response,
                                    GateAdmission hostAdmission, GateAdmission globalAdmission) {
        boolean throttled = settings.throttleStatusCodes().contains((int) response.statusCode());
        long now = currentTimeMillis.getAsLong();
        long retryAfterMillis = retryAfterMillis(retryAfter(response), now);
        if (settings.pauseMode() == ThrottleSettings.PauseMode.FIXED) {
            if (throttled) {
                synchronized (globalPauseLock) {
                    beginGlobalPause(now, Math.max(settings.fixedPauseMillis(), retryAfterMillis), "fixed");
                }
            }
            return;
        }
        if (settings.pauseMode() != ThrottleSettings.PauseMode.SMART) {
            return;
        }

        reportSmartOutcome(host.smartCircuit, host.key, throttled, retryAfterMillis, hostAdmission);
        reportSmartOutcome(globalSmartCircuit, host.key, throttled, retryAfterMillis, globalAdmission);
    }

    private GateAdmission awaitSmartCircuit(SmartCircuit circuit, boolean claimHalfOpenProbe) {
        if (settings.pauseMode() != ThrottleSettings.PauseMode.SMART) {
            return GateAdmission.OPEN;
        }
        synchronized (circuit) {
            while (true) {
                long now = currentTimeMillis.getAsLong();
                long remaining = circuit.pauseUntilMillis - now;
                if (remaining > 0) {
                    try {
                        circuit.wait(Math.min(remaining, 1_000L));
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return GateAdmission.INTERRUPTED;
                    }
                    continue;
                }
                if (circuit.pauseUntilMillis > 0) {
                    circuit.pauseUntilMillis = 0;
                    circuit.halfOpen = true;
                    circuit.halfOpenSuccesses = 0;
                    circuit.halfOpenProbeInFlight = false;
                    logger.accept(circuit.label + " cooldown ended; cautiously probing before full resume.");
                }
                if (!circuit.halfOpen || !claimHalfOpenProbe) {
                    return GateAdmission.OPEN;
                }
                if (!circuit.halfOpenProbeInFlight) {
                    circuit.halfOpenProbeInFlight = true;
                    return GateAdmission.HALF_OPEN_PROBE;
                }
                try {
                    circuit.wait(1_000L);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return GateAdmission.INTERRUPTED;
                }
            }
        }
    }

    private void reportSmartOutcome(SmartCircuit circuit, String hostKey, boolean throttled,
                                    long retryAfterMillis, GateAdmission admission) {
        long now = currentTimeMillis.getAsLong();
        synchronized (circuit) {
            if (admission == GateAdmission.HALF_OPEN_PROBE) {
                circuit.halfOpenProbeInFlight = false;
                if (throttled) {
                    beginSmartPause(circuit, now, retryAfterMillis, "half-open probe was throttled");
                } else {
                    circuit.halfOpenSuccesses++;
                    if (circuit.halfOpenSuccesses >= HALF_OPEN_SUCCESSES) {
                        circuit.halfOpen = false;
                        circuit.observations.clear();
                        circuit.consecutiveThrottles = 0;
                        logger.accept(circuit.label + " resumed after " + HALF_OPEN_SUCCESSES
                            + " successful recovery probes.");
                    }
                    circuit.notifyAll();
                }
                return;
            }

            // Responses already in flight when a circuit trips must not immediately retrip it.
            if (circuit.pauseUntilMillis > now || circuit.halfOpen) {
                return;
            }
            if (circuit.lastThrottleMillis > 0
                && now - circuit.lastThrottleMillis > SMART_RESET_AFTER_MILLIS) {
                circuit.pauseLevel = 0;
                circuit.observations.clear();
                circuit.consecutiveThrottles = 0;
            }
            if (throttled) {
                circuit.lastThrottleMillis = now;
                circuit.consecutiveThrottles++;
            } else {
                circuit.consecutiveThrottles = 0;
            }
            circuit.observations.addLast(new SmartObservation(throttled, hostKey));
            while (circuit.observations.size() > SMART_WINDOW_SIZE) {
                circuit.observations.removeFirst();
            }

            int throttles = 0;
            Set<String> throttledHosts = new HashSet<>();
            for (SmartObservation observation : circuit.observations) {
                if (observation.throttled()) {
                    throttles++;
                    throttledHosts.add(observation.hostKey());
                }
            }
            boolean enoughHosts = !circuit.requireMultipleHosts || throttledHosts.size() >= 2;
            boolean streakTrip = circuit.consecutiveThrottles >= SMART_THROTTLE_STREAK;
            boolean ratioTrip = circuit.observations.size() >= SMART_MIN_WINDOW_SIZE
                && throttles >= SMART_MIN_THROTTLES
                && throttles / (double) circuit.observations.size() >= SMART_THROTTLE_RATIO;
            if (enoughHosts && (streakTrip || ratioTrip)) {
                String reason = streakTrip
                    ? circuit.consecutiveThrottles + " consecutive throttle responses"
                    : throttles + " of the last " + circuit.observations.size()
                        + " responses were throttled";
                beginSmartPause(circuit, now, retryAfterMillis, reason);
            }
        }
    }

    private void beginSmartPause(SmartCircuit circuit, long now, long retryAfterMillis, String reason) {
        long computed = Math.min(120_000L, 10_000L << Math.min(circuit.pauseLevel, 4));
        long durationMillis = Math.max(computed, retryAfterMillis);
        circuit.pauseLevel++;
        circuit.pauseUntilMillis = Math.max(circuit.pauseUntilMillis, now + durationMillis);
        circuit.halfOpen = false;
        circuit.halfOpenProbeInFlight = false;
        circuit.halfOpenSuccesses = 0;
        circuit.observations.clear();
        circuit.consecutiveThrottles = 0;
        logger.accept(circuit.label + " Smart Pause: " + reason + "; waiting "
            + durationMillis + " ms before recovery probes.");
        circuit.notifyAll();
    }

    private void cancelHalfOpenProbe(SmartCircuit circuit, GateAdmission admission) {
        if (admission != GateAdmission.HALF_OPEN_PROBE) {
            return;
        }
        synchronized (circuit) {
            circuit.halfOpenProbeInFlight = false;
            circuit.notifyAll();
        }
    }

    private enum GateAdmission { OPEN, HALF_OPEN_PROBE, INTERRUPTED }

    private record SmartObservation(boolean throttled, String hostKey) {}

    private static final class SmartCircuit {
        private final String label;
        private final boolean requireMultipleHosts;
        private final Deque<SmartObservation> observations = new ArrayDeque<>();
        private long pauseUntilMillis;
        private long lastThrottleMillis;
        private int pauseLevel;
        private int consecutiveThrottles;
        private boolean halfOpen;
        private boolean halfOpenProbeInFlight;
        private int halfOpenSuccesses;

        private SmartCircuit(String label, boolean requireMultipleHosts) {
            this.label = label;
            this.requireMultipleHosts = requireMultipleHosts;
        }
    }

    private void beginGlobalPause(long now, long durationMillis, String mode) {
        globalPauseUntilMillis = Math.max(globalPauseUntilMillis, now + durationMillis);
        logger.accept("Global " + mode + " throttle pause: " + durationMillis
            + " ms before scan requests resume.");
        globalPauseLock.notifyAll();
    }

    private long retryAfterMillis(String value, long nowMillis) {
        if (value == null || value.isBlank()) return 0L;
        try {
            return Math.max(0L, Long.parseLong(value.trim()) * 1_000L);
        } catch (NumberFormatException ignored) {
            try {
                return Math.max(0L, java.time.ZonedDateTime.parse(value.trim()).toInstant().toEpochMilli() - nowMillis);
            } catch (Exception ignoredAgain) {
                return 0L;
            }
        }
    }

    /** True if the given status code is treated as a rate-limit signal. */
    public boolean isThrottleStatusCode(int statusCode) {
        return settings.throttleStatusCodes().contains(statusCode);
    }

    /** Current adaptive rate (req/s) for a host, or 0 if none seen yet. Telemetry for the UI. */
    public double currentRateForHost(String hostKey) {
        HostState host = hosts.get(hostKey);
        return host == null ? 0 : host.controller.currentRatePerSecond();
    }

    /** The per-host controller, exposed for tests and telemetry. */
    AdaptiveRateController controllerForHost(String hostKey) {
        HostState host = hosts.get(hostKey);
        return host == null ? null : host.controller;
    }

    /** Requests that have crossed all admission gates and are currently waiting for a response. */
    public int inFlightRequestCount() {
        return inFlightRequests.get();
    }

    /** Freezes every existing and subsequently-created host controller during a manual UI pause. */
    public void manualPause() {
        synchronized (manualPauseLock) {
            if (manuallyPaused) return;
            manuallyPaused = true;
            hosts.values().forEach(host -> host.controller.manualPause());
        }
    }

    /** Resumes safely without accumulated burst credit; long pauses cold-start learned host rates. */
    public void manualResume() {
        int coldStarted = 0;
        synchronized (manualPauseLock) {
            if (!manuallyPaused) return;
            manuallyPaused = false;
            for (HostState host : hosts.values()) {
                if (host.controller.manualResume()) coldStarted++;
            }
        }
        logger.accept("Manual resume: discarded throttle burst credit"
            + (coldStarted > 0 ? "; cold-started " + coldStarted + " host rate(s)." : "."));
    }

    /** Remaining Sweep-wide CDN/WAF cooldown, exposed for tests and telemetry. */
    long globalPauseRemainingMillis() {
        synchronized (globalPauseLock) {
            long fixedRemaining = Math.max(0L, globalPauseUntilMillis - currentTimeMillis.getAsLong());
            synchronized (globalSmartCircuit) {
                long smartRemaining = Math.max(0L,
                    globalSmartCircuit.pauseUntilMillis - currentTimeMillis.getAsLong());
                return Math.max(fixedRemaining, smartRemaining);
            }
        }
    }

    /** Remaining host-local Smart Pause cooldown, exposed for tests and telemetry. */
    long hostPauseRemainingMillis(String hostKey) {
        HostState host = hosts.get(hostKey);
        if (host == null) return 0L;
        synchronized (host.smartCircuit) {
            return Math.max(0L, host.smartCircuit.pauseUntilMillis - currentTimeMillis.getAsLong());
        }
    }

    boolean hostIsHalfOpen(String hostKey) {
        HostState host = hosts.get(hostKey);
        if (host == null) return false;
        synchronized (host.smartCircuit) {
            return host.smartCircuit.halfOpen;
        }
    }

    static String hostKey(HttpRequest request) {
        try {
            URI uri = URI.create(request.url());
            int port = uri.getPort();
            if (port < 0) {
                port = "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
            }
            return (uri.getScheme() == null ? "http" : uri.getScheme().toLowerCase())
                + "://" + uri.getHost().toLowerCase() + ":" + port;
        } catch (Exception ignored) {
            try {
                return request.httpService().toString();
            } catch (Exception ignoredAgain) {
                return "unknown-host";
            }
        }
    }

    private static String retryAfter(HttpResponse response) {
        try {
            return response.headerValue("Retry-After");
        } catch (Exception ignored) {
            return null;
        }
    }

    private static Consumer<String> loggerFor(MontoyaApi api) {
        if (api == null) {
            return message -> {};
        }
        return message -> {
            try {
                if (api.logging() != null) {
                    api.logging().logToOutput(message);
                }
            } catch (Exception ignored) {
                // logging is best-effort
            }
        };
    }

    private final class HostState {
        private final String key;
        private final AdaptiveRateController controller;
        private final Semaphore permits = new Semaphore(settings.perHostConcurrency(), true);
        private final SmartCircuit smartCircuit;

        private HostState(String hostKey) {
            this.key = hostKey;
            this.smartCircuit = new SmartCircuit("Host " + hostKey, false);
            AdaptiveRateController.Tuning tuning = tuningOverride != null ? tuningOverride : settings.tuning();
            this.controller = new AdaptiveRateController(tuning,
                settings.throttleStatusCodes(), nanoTime, currentTimeMillis, hostKey, logger);
            synchronized (manualPauseLock) {
                if (manuallyPaused) {
                    this.controller.manualPause();
                }
            }
        }
    }
}
