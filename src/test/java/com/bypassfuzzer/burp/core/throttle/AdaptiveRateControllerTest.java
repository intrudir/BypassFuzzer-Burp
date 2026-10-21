package com.bypassfuzzer.burp.core.throttle;
import com.bypassfuzzer.core.throttle.AdaptiveRateController;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AdaptiveRateControllerTest {

    private static final long MS = 1_000_000L;
    private static final long SECOND = 1_000_000_000L;

    private static AdaptiveRateController controller(RateLimitSimulator.Clock clock) {
        return controller(clock, AdaptiveRateController.Tuning.defaults());
    }

    private static AdaptiveRateController controller(RateLimitSimulator.Clock clock,
                                                     AdaptiveRateController.Tuning tuning) {
        return new AdaptiveRateController(tuning, Set.of(429, 503), clock::nanos, clock::millis, "sim", null);
    }

    // -- Unit behaviour ------------------------------------------------------

    @Test
    void firstAcquireIsGrantedImmediately() {
        RateLimitSimulator.Clock clock = new RateLimitSimulator.Clock(SECOND);
        AdaptiveRateController controller = controller(clock);

        AdaptiveRateController.Reservation reservation = controller.tryAcquire();

        assertTrue(reservation.granted());
        assertEquals(0, reservation.waitNanos());
    }

    @Test
    void staleGenerationReportIsIgnored() {
        RateLimitSimulator.Clock clock = new RateLimitSimulator.Clock(SECOND);
        AdaptiveRateController controller = controller(clock);
        long staleGeneration = controller.generation() + 5; // any generation that is not the current one

        double before = controller.currentRatePerSecond();
        controller.report(429, null, staleGeneration);

        assertEquals(before, controller.currentRatePerSecond(),
            "a report from a superseded generation must not change the rate");
    }

    @Test
    void throttleMultiplicativelyDecreasesRateAndRecordsCeiling() {
        RateLimitSimulator.Clock clock = new RateLimitSimulator.Clock(SECOND);
        AdaptiveRateController.Tuning tuning = AdaptiveRateController.Tuning.defaults();
        AdaptiveRateController controller = controller(clock, tuning);

        double rateBefore = controller.currentRatePerSecond();
        controller.report(429, null, controller.generation());

        assertEquals(rateBefore, controller.ceilingEstimatePerSecond(), 1e-9);
        assertEquals(rateBefore * tuning.mdFactor(), controller.currentRatePerSecond(), 1e-6);
        assertEquals(AdaptiveRateController.Phase.STEADY, controller.phase());
    }

    @Test
    void retryAfterHeaderPausesAdmission() {
        RateLimitSimulator.Clock clock = new RateLimitSimulator.Clock(SECOND);
        AdaptiveRateController controller = controller(clock);

        controller.report(429, "2", controller.generation());

        assertTrue(controller.isPaused());
        AdaptiveRateController.Reservation reservation = controller.tryAcquire();
        assertFalse(reservation.granted());
        assertTrue(reservation.waitNanos() >= TimeUnit.SECONDS.toNanos(1),
            "must wait out most of the Retry-After window");

        clock.set(clock.nanos() + TimeUnit.SECONDS.toNanos(2));
        assertFalse(controller.isPaused());
    }

    @Test
    void longManualPauseDiscardsBurstCreditAndColdStartsTheRate() {
        RateLimitSimulator.Clock clock = new RateLimitSimulator.Clock(SECOND);
        AdaptiveRateController.Tuning tuning = AdaptiveRateController.Tuning.defaults();
        AdaptiveRateController controller = controller(clock, tuning);
        AdaptiveRateController.Reservation initial = controller.tryAcquire();
        clock.set(clock.nanos() + TimeUnit.MILLISECONDS.toNanos(600));
        controller.report(200, null, initial.generation());
        assertTrue(controller.currentRatePerSecond() > tuning.initialRate());

        controller.manualPause();
        clock.set(clock.nanos() + TimeUnit.MINUTES.toNanos(10));
        assertFalse(controller.tryAcquire().granted(),
            "manual pause must not accrue or consume admission tokens");

        assertTrue(controller.manualResume());
        assertEquals(tuning.initialRate(), controller.currentRatePerSecond(), 1e-9);
        assertTrue(controller.tryAcquire().granted(), "resume should release one safe request");
        assertFalse(controller.tryAcquire().granted(),
            "ten minutes paused must not become a full token-bucket burst");
    }

    @Test
    void shortManualPauseKeepsTheLearnedRateButStillDropsBurstCredit() {
        RateLimitSimulator.Clock clock = new RateLimitSimulator.Clock(SECOND);
        AdaptiveRateController controller = controller(clock);
        AdaptiveRateController.Reservation initial = controller.tryAcquire();
        clock.set(clock.nanos() + TimeUnit.MILLISECONDS.toNanos(600));
        controller.report(200, null, initial.generation());
        double learnedRate = controller.currentRatePerSecond();

        controller.manualPause();
        clock.set(clock.nanos() + TimeUnit.SECONDS.toNanos(10));

        assertFalse(controller.manualResume());
        assertEquals(learnedRate, controller.currentRatePerSecond(), 1e-9);
        assertTrue(controller.tryAcquire().granted());
        assertFalse(controller.tryAcquire().granted());
    }

    @Test
    void burstOfSimultaneousThrottlesCountsAsOneLossEvent() {
        RateLimitSimulator.Clock clock = new RateLimitSimulator.Clock(SECOND);
        AdaptiveRateController.Tuning tuning = AdaptiveRateController.Tuning.defaults();
        AdaptiveRateController controller = controller(clock, tuning);

        double rateBefore = controller.currentRatePerSecond();
        long generation = controller.generation();
        controller.report(429, null, generation); // first loss -> one MD, generation bumps
        double afterOne = controller.currentRatePerSecond();
        // A cluster of in-flight throttles carrying the same (now-stale) generation must not
        // compound the decrease.
        controller.report(429, null, generation);
        controller.report(429, null, generation);

        assertEquals(rateBefore * tuning.mdFactor(), afterOne, 1e-6);
        assertEquals(afterOne, controller.currentRatePerSecond(), 1e-6);
    }

    @Test
    void retryAfterHttpDateIsParsed() {
        long nowMs = 1_000_000_000_000L;
        String httpDate = java.time.ZonedDateTime.ofInstant(
                java.time.Instant.ofEpochMilli(nowMs + 5_000),
                java.time.ZoneOffset.UTC)
            .format(java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME);

        long parsed = AdaptiveRateController.parseRetryAfterMs(httpDate, nowMs);

        assertTrue(parsed >= 4_000 && parsed <= 5_000, "expected ~5s, got " + parsed);
    }

    // -- Convergence assertions ---------------------------------------------

    private RateLimitSimulator.Metrics converge(RateLimitSimulator.ServerModel server, int requests,
                                                double warmupFraction) {
        RateLimitSimulator.Clock clock = new RateLimitSimulator.Clock(SECOND);
        AdaptiveRateController controller = controller(clock);
        List<RateLimitSimulator.Sample> samples = RateLimitSimulator.run(controller, clock, server, requests);
        return RateLimitSimulator.steadyState(samples, warmupFraction);
    }

    @Test
    void ridesJustUnderASlidingWindowLimit() {
        RateLimitSimulator.Metrics steady =
            converge(RateLimitSimulator.slidingWindow(50, SECOND, 50 * MS, true), 6000, 0.4);

        assertTrue(steady.goodputRps() >= 0.88 * 50,
            "expected >=88% of a 50/s ceiling, got " + steady.goodputRps());
        assertTrue(steady.throttleRate() <= 0.05,
            "expected <=5% steady-state throttle, got " + steady.throttleRate());
    }

    @Test
    void ridesJustUnderAHighRateSlidingWindow() {
        RateLimitSimulator.Metrics steady =
            converge(RateLimitSimulator.slidingWindow(200, SECOND, 15 * MS, true), 12000, 0.4);

        assertTrue(steady.goodputRps() >= 0.90 * 200,
            "expected >=90% of a 200/s ceiling, got " + steady.goodputRps());
        assertTrue(steady.throttleRate() <= 0.03,
            "expected <=3% steady-state throttle, got " + steady.throttleRate());
    }

    @Test
    void ridesJustUnderATokenBucketLimit() {
        RateLimitSimulator.Metrics steady =
            converge(RateLimitSimulator.tokenBucket(30, 40, 40 * MS), 5000, 0.4);

        assertTrue(steady.goodputRps() >= 0.90 * 30,
            "expected >=90% of a 30/s ceiling, got " + steady.goodputRps());
        assertTrue(steady.throttleRate() <= 0.05,
            "expected <=5% steady-state throttle, got " + steady.throttleRate());
    }

    @Test
    void unlimitedHostRampsToTheRateCapWithoutThrottling() {
        RateLimitSimulator.Clock clock = new RateLimitSimulator.Clock(SECOND);
        AdaptiveRateController controller = controller(clock);
        List<RateLimitSimulator.Sample> samples =
            RateLimitSimulator.run(controller, clock, RateLimitSimulator.unlimited(20 * MS), 4000);
        RateLimitSimulator.Metrics steady = RateLimitSimulator.steadyState(samples, 0.4);

        assertEquals(0, steady.throttled(), "an unlimited host must never be throttled");
        assertEquals(AdaptiveRateController.Tuning.defaults().maxRate(),
            controller.currentRatePerSecond(), 1e-6, "should ramp to the configured rate cap");
    }

    @Test
    void reconvergesWhenTheLimitDropsMidRun() {
        RateLimitSimulator.ServerModel server = RateLimitSimulator.switchingByCount(
            RateLimitSimulator.slidingWindow(100, SECOND, 20 * MS, true),
            RateLimitSimulator.slidingWindow(20, SECOND, 20 * MS, true),
            3000);
        RateLimitSimulator.Clock clock = new RateLimitSimulator.Clock(SECOND);
        AdaptiveRateController controller = controller(clock);
        List<RateLimitSimulator.Sample> samples = RateLimitSimulator.run(controller, clock, server, 6000);

        // Measure only the tail, well after the drop, once the controller has re-converged.
        RateLimitSimulator.Metrics tail = RateLimitSimulator.steadyState(samples, 0.75);
        double finalRate = controller.currentRatePerSecond();
        assertTrue(finalRate >= 0.7 * 20 && finalRate <= 1.3 * 20,
            "should have re-converged near the new 20/s ceiling, got " + finalRate);
        assertTrue(tail.goodputRps() <= 24,
            "should have backed down from the old 100/s rate, got " + tail.goodputRps());
        assertTrue(tail.throttleRate() <= 0.06,
            "should re-stabilise with low throttle, got " + tail.throttleRate());
    }

    // -- Convergence diagnostics --------------------------------------------
    // Prints steady-state behaviour across server models so the control-law constants can be tuned.

    @Test
    void printConvergenceMatrix() {
        report("sliding 50/s, 50ms",
            RateLimitSimulator.slidingWindow(50, SECOND, 50 * MS, true), 50.0, 6000);
        report("sliding 20/s, 80ms, no Retry-After",
            RateLimitSimulator.slidingWindow(20, SECOND, 80 * MS, false), 20.0, 3000);
        report("sliding 200/s, 15ms",
            RateLimitSimulator.slidingWindow(200, SECOND, 15 * MS, true), 200.0, 12000);
        report("fixed 100/s, 30ms",
            RateLimitSimulator.fixedWindow(100, SECOND, 30 * MS, true), 100.0, 8000);
        report("token-bucket 30/s burst40, 40ms",
            RateLimitSimulator.tokenBucket(30, 40, 40 * MS), 30.0, 5000);
        report("sliding 10/10s (slow), 100ms",
            RateLimitSimulator.slidingWindow(10, 10 * SECOND, 100 * MS, true), 1.0, 400);
        report("unlimited, 20ms",
            RateLimitSimulator.unlimited(20 * MS), Double.NaN, 4000);
    }

    /** Scenario for the tuning sweep: a fresh server per trial, its true limit, and a weight. */
    private record Scenario(String name, java.util.function.Supplier<RateLimitSimulator.ServerModel> server,
                            double limit, double weight, int requests) {}

    private static List<Scenario> sweepScenarios() {
        return List.of(
            new Scenario("sliding50", () -> RateLimitSimulator.slidingWindow(50, SECOND, 50 * MS, true), 50, 2.0, 6000),
            new Scenario("sliding20noRA", () -> RateLimitSimulator.slidingWindow(20, SECOND, 80 * MS, false), 20, 2.0, 3000),
            new Scenario("sliding200", () -> RateLimitSimulator.slidingWindow(200, SECOND, 15 * MS, true), 200, 2.0, 12000),
            new Scenario("tokenbucket30", () -> RateLimitSimulator.tokenBucket(30, 40, 40 * MS), 30, 2.0, 5000),
            new Scenario("fixed100", () -> RateLimitSimulator.fixedWindow(100, SECOND, 30 * MS, true), 100, 1.0, 8000),
            new Scenario("sliding100lat5", () -> RateLimitSimulator.slidingWindow(100, SECOND, 5 * MS, true), 100, 1.5, 9000)
        );
    }

    @Test
    void printTuningSweep() {
        AdaptiveRateController.Tuning base = AdaptiveRateController.Tuning.defaults();
        // Candidate variations around the base, exploring the levers that trade sliding-window
        // smoothness against fixed-window ceiling reclamation.
        List<AdaptiveRateController.Tuning> candidates = new ArrayList<>();
        for (double bucket : new double[]{0.4, 0.6, 0.8}) {
            for (double md : new double[]{0.80, 0.85}) {
                for (double probe : new double[]{0.02, 0.03}) {
                    for (long interval : new long[]{350, 500}) {
                        candidates.add(new AdaptiveRateController.Tuning(
                            base.initialRate(), base.minRate(), base.maxRate(), bucket,
                            base.slowStartGrowth(), md, base.approachFraction(), probe,
                            base.probeAccelSeconds(), base.maxStepFraction(), base.minStep(),
                            interval, base.mdCooldownMs()));
                    }
                }
            }
        }

        List<String> rows = new ArrayList<>();
        for (AdaptiveRateController.Tuning tuning : candidates) {
            double weightedUtil = 0;
            double totalWeight = 0;
            double worstThrottle = 0;
            for (Scenario scenario : sweepScenarios()) {
                RateLimitSimulator.Clock clock = new RateLimitSimulator.Clock(SECOND);
                AdaptiveRateController controller = controller(clock, tuning);
                List<RateLimitSimulator.Sample> samples =
                    RateLimitSimulator.run(controller, clock, scenario.server().get(), scenario.requests());
                RateLimitSimulator.Metrics steady = RateLimitSimulator.steadyState(samples, 0.4);
                weightedUtil += scenario.weight() * (steady.goodputRps() / scenario.limit());
                totalWeight += scenario.weight();
                worstThrottle = Math.max(worstThrottle, steady.throttleRate());
            }
            double score = weightedUtil / totalWeight - (worstThrottle > 0.05 ? (worstThrottle - 0.05) * 4 : 0);
            rows.add(String.format("score=%.3f  util=%4.1f%%  worstThrottle=%4.1f%%  bucket=%.1f md=%.2f probe=%.2f interval=%d",
                score, 100 * weightedUtil / totalWeight, 100 * worstThrottle,
                tuning.bucketSeconds(), tuning.mdFactor(), tuning.probeFraction(), tuning.increaseIntervalMs()));
        }
        rows.sort((a, b) -> b.substring(6, 11).compareTo(a.substring(6, 11)));
        System.out.println("=== tuning sweep (best first) ===");
        rows.forEach(System.out::println);
    }

    private void report(String name, RateLimitSimulator.ServerModel server, double limit, int requests) {
        RateLimitSimulator.Clock clock = new RateLimitSimulator.Clock(SECOND);
        AdaptiveRateController controller = controller(clock);
        List<RateLimitSimulator.Sample> samples = RateLimitSimulator.run(controller, clock, server, requests);
        RateLimitSimulator.Metrics steady = RateLimitSimulator.steadyState(samples, 0.4);
        double utilisation = Double.isNaN(limit) ? Double.NaN : steady.goodputRps() / limit;
        System.out.printf(
            "%-34s goodput=%7.1f/s  limit=%6s  util=%5s  throttle=%5.1f%%  finalRate=%6.1f  ceiling=%6.1f%n",
            name,
            steady.goodputRps(),
            Double.isNaN(limit) ? "inf" : String.format("%.0f", limit),
            Double.isNaN(utilisation) ? "  n/a" : String.format("%3.0f%%", utilisation * 100),
            steady.throttleRate() * 100,
            controller.currentRatePerSecond(),
            controller.ceilingEstimatePerSecond());
    }
}
