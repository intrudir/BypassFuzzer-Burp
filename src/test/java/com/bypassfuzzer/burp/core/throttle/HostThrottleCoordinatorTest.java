package com.bypassfuzzer.burp.core.throttle;
import com.bypassfuzzer.core.throttle.AdaptiveRateController;
import com.bypassfuzzer.core.throttle.ThrottleSettings;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.ExecutionPauseController;
import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class HostThrottleCoordinatorTest {

    private static HttpRequest requestTo(String url) {
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn(url);
        return request;
    }

    private static HttpResponse response(int status, String retryAfter) {
        HttpResponse response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn((short) status);
        when(response.headerValue("Retry-After")).thenReturn(retryAfter);
        return response;
    }

    private static HostThrottleCoordinator coordinator(ThrottleSettings settings) {
        return new HostThrottleCoordinator(settings, message -> {},
            System::nanoTime, System::currentTimeMillis, null);
    }

    @Test
    void eachHostGetsAnIndependentController() {
        HostThrottleCoordinator coordinator = coordinator(ThrottleSettings.defaults());
        String hostA = "https://a.example.com:443";
        String hostB = "https://b.example.com:443";

        coordinator.send(requestTo(hostA + "/x"), () -> response(200, null));
        double rateABefore = coordinator.currentRateForHost(hostA);
        coordinator.send(requestTo(hostB + "/y"), () -> response(429, null));

        assertTrue(coordinator.currentRateForHost(hostB) < rateABefore,
            "a 429 on host B must lower only B's rate");
        assertTrue(coordinator.currentRateForHost(hostA) >= rateABefore,
            "host A must be unaffected by host B's throttle");
    }

    @Test
    void retryAfterHeaderPausesTheHostController() {
        HostThrottleCoordinator coordinator = coordinator(ThrottleSettings.defaults());
        String host = "https://c.example.com:443";

        coordinator.send(requestTo(host + "/z"), () -> response(429, "2"));

        AdaptiveRateController controller = coordinator.controllerForHost(host);
        assertNotNull(controller);
        assertTrue(controller.isPaused(), "a Retry-After response must pause the host controller");
    }

    private static HostThrottleCoordinator fastCoordinator(ThrottleSettings settings,
                                                            AtomicLong currentTimeMillis) {
        AdaptiveRateController.Tuning fast = new AdaptiveRateController.Tuning(
            100_000, 1, 1_000_000, 100, 2, 0.85, 0.3, 0.02, 8, 0.12, 1, 500, 750);
        return new HostThrottleCoordinator(settings, message -> {}, System::nanoTime,
            currentTimeMillis::get, fast);
    }

    @Test
    void fixedPauseStartsAGlobalCooldownOnTheFirstThrottleResponse() {
        ThrottleSettings settings = new ThrottleSettings(Set.of(429), 4, 2, 100,
            ThrottleSettings.Posture.RIDE_HARD, ThrottleSettings.PauseMode.FIXED, 30_000L);
        HostThrottleCoordinator coordinator = coordinator(settings);

        coordinator.send(requestTo("https://a.example.com/x"), () -> response(429, null));

        assertTrue(coordinator.globalPauseRemainingMillis() >= 29_000L);
    }

    @Test
    void smartPauseToleratesSparseThrottleResponses() {
        ThrottleSettings settings = new ThrottleSettings(Set.of(429), 4, 2, 100,
            ThrottleSettings.Posture.RIDE_HARD, ThrottleSettings.PauseMode.SMART, 30_000L);
        AtomicLong clock = new AtomicLong(1_000L);
        HostThrottleCoordinator coordinator = fastCoordinator(settings, clock);
        String host = "https://a.example.com:443";

        for (int i = 0; i < 50; i++) {
            int status = i % 6 == 0 ? 429 : 200;
            coordinator.send(requestTo(host + "/" + i), () -> response(status, null));
        }

        assertEquals(0L, coordinator.hostPauseRemainingMillis(host));
        assertEquals(0L, coordinator.globalPauseRemainingMillis());
    }

    @Test
    void smartPauseStopsOnlyAHostAfterASustainedThrottleStreak() {
        ThrottleSettings settings = new ThrottleSettings(Set.of(429), 4, 2, 100,
            ThrottleSettings.Posture.RIDE_HARD, ThrottleSettings.PauseMode.SMART, 30_000L);
        AtomicLong clock = new AtomicLong(1_000L);
        HostThrottleCoordinator coordinator = fastCoordinator(settings, clock);
        String host = "https://a.example.com:443";

        for (int i = 0; i < 8; i++) {
            coordinator.send(requestTo(host + "/" + i), () -> response(429, null));
        }

        assertTrue(coordinator.hostPauseRemainingMillis(host) >= 10_000L);
        assertEquals(0L, coordinator.globalPauseRemainingMillis(),
            "one saturated host must not pause unrelated Sweep hosts");
    }

    @Test
    void smartPauseDetectsACorrelatedHighThrottleRatioAcrossHosts() {
        ThrottleSettings settings = new ThrottleSettings(Set.of(429), 8, 4, 100,
            ThrottleSettings.Posture.RIDE_HARD, ThrottleSettings.PauseMode.SMART, 30_000L);
        AtomicLong clock = new AtomicLong(1_000L);
        HostThrottleCoordinator coordinator = fastCoordinator(settings, clock);

        for (int i = 0; i < 25; i++) {
            String host = "https://" + (char) ('a' + i % 3) + ".example.com:443";
            int status = i < 20 && i % 2 == 0 ? 429 : 200;
            coordinator.send(requestTo(host + "/" + i), () -> response(status, null));
        }

        assertTrue(coordinator.globalPauseRemainingMillis() >= 10_000L,
            "a 40% throttle ratio spanning hosts should trip the shared circuit breaker");
    }

    @Test
    void smartPauseRequiresFiveSuccessfulHalfOpenProbesBeforeResuming() {
        ThrottleSettings settings = new ThrottleSettings(Set.of(429), 4, 2, 100,
            ThrottleSettings.Posture.RIDE_HARD, ThrottleSettings.PauseMode.SMART, 30_000L);
        AtomicLong clock = new AtomicLong(1_000L);
        HostThrottleCoordinator coordinator = fastCoordinator(settings, clock);
        String host = "https://a.example.com:443";

        for (int i = 0; i < 8; i++) {
            coordinator.send(requestTo(host + "/blocked-" + i), () -> response(429, null));
        }
        clock.addAndGet(10_001L);

        for (int i = 0; i < 4; i++) {
            coordinator.send(requestTo(host + "/probe-" + i), () -> response(200, null));
            assertTrue(coordinator.hostIsHalfOpen(host));
        }
        coordinator.send(requestTo(host + "/probe-4"), () -> response(200, null));

        assertFalse(coordinator.hostIsHalfOpen(host));
        assertEquals(0L, coordinator.hostPauseRemainingMillis(host));
    }

    @Test
    void retryAfterExtendsTheFixedGlobalCooldown() {
        ThrottleSettings settings = new ThrottleSettings(Set.of(429), 4, 2, 100,
            ThrottleSettings.Posture.RIDE_HARD, ThrottleSettings.PauseMode.FIXED, 5_000L);
        HostThrottleCoordinator coordinator = coordinator(settings);

        coordinator.send(requestTo("https://a.example.com/x"), () -> response(429, "30"));

        assertTrue(coordinator.globalPauseRemainingMillis() >= 29_000L);
    }

    @Test
    void finalPauseGateStopsAWorkerThatWasAlreadyQueuedForAPermit() throws Exception {
        ThrottleSettings settings = new ThrottleSettings(Set.of(429), 1, 1, 100,
            ThrottleSettings.Posture.RIDE_HARD);
        HostThrottleCoordinator coordinator = coordinator(settings);
        ExecutionPauseController pause = new ExecutionPauseController();
        CountDownLatch firstSent = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        CountDownLatch secondSent = new CountDownLatch(1);

        Thread first = new Thread(() -> coordinator.send(requestTo("https://a.example.com/first"), () -> {
            firstSent.countDown();
            try {
                releaseFirst.await(2, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return response(200, null);
        }));
        first.start();
        assertTrue(firstSent.await(2, TimeUnit.SECONDS));
        assertEquals(1, coordinator.inFlightRequestCount());

        Thread second = new Thread(() -> coordinator.send(requestTo("https://a.example.com/second"), () -> {
            secondSent.countDown();
            return response(200, null);
        }, () -> pause.awaitIfPaused(() -> true)));
        second.start();
        TimeUnit.MILLISECONDS.sleep(100);
        pause.pause();
        releaseFirst.countDown();
        first.join(2_000L);

        assertFalse(secondSent.await(200, TimeUnit.MILLISECONDS));
        assertEquals(0, coordinator.inFlightRequestCount(),
            "a pause-blocked admission has not been sent and must not count as in flight");

        pause.resume();
        assertTrue(secondSent.await(2, TimeUnit.SECONDS));
        second.join(2_000L);
        assertFalse(second.isAlive());
    }

    @Test
    void manualPauseAlsoFreezesAHostCreatedAfterThePause() throws Exception {
        ThrottleSettings settings = new ThrottleSettings(Set.of(429), 2, 2, 100,
            ThrottleSettings.Posture.RIDE_HARD);
        HostThrottleCoordinator coordinator = coordinator(settings);
        CountDownLatch sent = new CountDownLatch(1);
        coordinator.manualPause();

        Thread worker = new Thread(() -> coordinator.send(requestTo("https://new.example.com/request"), () -> {
            sent.countDown();
            return response(200, null);
        }));
        worker.start();

        assertFalse(sent.await(200, TimeUnit.MILLISECONDS));
        assertEquals(0, coordinator.inFlightRequestCount());

        coordinator.manualResume();
        assertTrue(sent.await(2, TimeUnit.SECONDS));
        worker.join(2_000L);
        assertFalse(worker.isAlive());
    }

    @Test
    void concurrencyNeverExceedsGlobalOrPerHostBounds() throws Exception {
        int globalLimit = 4;
        int perHostLimit = 2;
        ThrottleSettings settings = new ThrottleSettings(Set.of(429), globalLimit, perHostLimit, 400,
            ThrottleSettings.Posture.RIDE_HARD);
        // Permissive tuning so admission never blocks on pacing -- this isolates the semaphore bounds.
        AdaptiveRateController.Tuning fast = new AdaptiveRateController.Tuning(
            100_000, 1, 1_000_000, 100, 2, 0.85, 0.3, 0.02, 8, 0.12, 1, 500, 750);
        HostThrottleCoordinator coordinator = new HostThrottleCoordinator(settings, message -> {},
            System::nanoTime, System::currentTimeMillis, fast);

        AtomicInteger active = new AtomicInteger();
        AtomicInteger maxActive = new AtomicInteger();
        AtomicInteger maxPerHost = new AtomicInteger();
        AtomicInteger activeHostA = new AtomicInteger();
        CountDownLatch release = new CountDownLatch(1);

        ExecutorService pool = Executors.newFixedThreadPool(12);
        for (int i = 0; i < 12; i++) {
            boolean hostA = i % 2 == 0;
            String url = (hostA ? "https://a.example.com:443" : "https://b.example.com:443") + "/" + i;
            pool.submit(() -> coordinator.send(requestTo(url), () -> {
                int now = active.incrementAndGet();
                maxActive.updateAndGet(prev -> Math.max(prev, now));
                if (hostA) {
                    int perHost = activeHostA.incrementAndGet();
                    maxPerHost.updateAndGet(prev -> Math.max(prev, perHost));
                }
                try {
                    release.await(2, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                if (hostA) {
                    activeHostA.decrementAndGet();
                }
                active.decrementAndGet();
                return response(200, null);
            }));
        }

        // Let admissions overlap while suppliers are parked, then release and drain.
        TimeUnit.MILLISECONDS.sleep(400);
        assertTrue(maxActive.get() > 0, "expected some senders to be admitted");
        release.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));

        assertTrue(maxActive.get() <= globalLimit,
            "global in-flight " + maxActive.get() + " exceeded cap " + globalLimit);
        assertTrue(maxPerHost.get() <= perHostLimit,
            "per-host in-flight " + maxPerHost.get() + " exceeded cap " + perHostLimit);
    }
}
