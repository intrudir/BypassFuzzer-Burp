package com.bypassfuzzer.burp.core.throttle;
import com.bypassfuzzer.core.throttle.AdaptiveRateController;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.PriorityQueue;
import java.util.concurrent.TimeUnit;

/**
 * Deterministic discrete-event simulator that drives a real {@link AdaptiveRateController} against a
 * modelled rate-limited server on a virtual clock. Single-threaded and instant: virtual time jumps
 * to the next admission or the next in-flight response, so a run of tens of thousands of requests
 * completes in microseconds while still modelling in-flight concurrency (many requests outstanding
 * between admission and response).
 *
 * <p>The controller is exercised through the same {@link AdaptiveRateController#tryAcquire()} and
 * {@link AdaptiveRateController#report} entry points production uses, so there is no forked logic.</p>
 */
final class RateLimitSimulator {

    /** A server's decision for one arrival. */
    record Decision(boolean throttled, long retryAfterMs, long latencyNanos) {}

    interface ServerModel {
        Decision arrival(long nowNanos);
    }

    /** One recorded request outcome, keyed by the virtual time it was admitted. */
    record Sample(long sendNanos, boolean throttled) {}

    /** Mutable virtual clock shared by the controller and the simulator. */
    static final class Clock {
        private long nanos;

        Clock(long startNanos) {
            this.nanos = startNanos;
        }

        long nanos() {
            return nanos;
        }

        long millis() {
            return TimeUnit.NANOSECONDS.toMillis(nanos);
        }

        void set(long newNanos) {
            this.nanos = Math.max(this.nanos, newNanos);
        }
    }

    private record Event(long time, Decision decision, long generation, long sendNanos) {}

    private RateLimitSimulator() {}

    /**
     * Runs the controller until {@code targetRequests} have been admitted, then drains all in-flight
     * responses.
     *
     * @return the per-request samples in admission order.
     */
    static List<Sample> run(AdaptiveRateController controller, Clock clock, ServerModel server,
                            int targetRequests) {
        List<Sample> samples = new ArrayList<>(targetRequests);
        PriorityQueue<Event> events = new PriorityQueue<>((a, b) -> Long.compare(a.time(), b.time()));
        int sent = 0;
        // Safety bound so a mis-tuned controller can never hang the test.
        long maxIterations = (long) targetRequests * 100L + 100_000L;
        long iterations = 0;

        while (sent < targetRequests && iterations++ < maxIterations) {
            drainDue(controller, events, clock.nanos(), samples);

            AdaptiveRateController.Reservation reservation = controller.tryAcquire();
            if (reservation.granted()) {
                long now = clock.nanos();
                sent++;
                Decision decision = server.arrival(now);
                events.add(new Event(now + Math.max(0, decision.latencyNanos()), decision,
                    reservation.generation(), now));
            } else {
                long admitAt = clock.nanos() + reservation.waitNanos();
                long nextEvent = events.isEmpty() ? Long.MAX_VALUE : events.peek().time();
                clock.set(Math.min(admitAt, nextEvent));
            }
        }

        // Drain remaining in-flight responses.
        while (!events.isEmpty()) {
            Event event = events.poll();
            clock.set(event.time());
            report(controller, event, samples);
        }
        return samples;
    }

    private static void drainDue(AdaptiveRateController controller, PriorityQueue<Event> events,
                                 long now, List<Sample> samples) {
        while (!events.isEmpty() && events.peek().time() <= now) {
            report(controller, events.poll(), samples);
        }
    }

    private static void report(AdaptiveRateController controller, Event event, List<Sample> samples) {
        String retryAfter = event.decision().retryAfterMs() > 0
            ? Long.toString((event.decision().retryAfterMs() + 999) / 1000)
            : null;
        controller.report(event.decision().throttled() ? 429 : 200, retryAfter, event.generation());
        samples.add(new Sample(event.sendNanos(), event.decision().throttled()));
    }

    // -- Metrics -------------------------------------------------------------

    /** Aggregate metrics over a slice of samples. */
    record Metrics(int count, int throttled, double goodputRps, double throttleRate) {}

    /**
     * Computes steady-state metrics over the tail of a run, skipping a warmup fraction while the
     * controller is still hunting the ceiling.
     */
    static Metrics steadyState(List<Sample> samples, double warmupFraction) {
        List<Sample> ordered = new ArrayList<>(samples);
        ordered.sort((a, b) -> Long.compare(a.sendNanos(), b.sendNanos()));
        int from = (int) Math.floor(ordered.size() * warmupFraction);
        List<Sample> tail = ordered.subList(from, ordered.size());
        if (tail.size() < 2) {
            return new Metrics(tail.size(), 0, 0, 0);
        }
        int throttled = 0;
        for (Sample sample : tail) {
            if (sample.throttled()) {
                throttled++;
            }
        }
        long spanNanos = tail.get(tail.size() - 1).sendNanos() - tail.get(0).sendNanos();
        double spanSeconds = spanNanos / 1_000_000_000.0;
        int succeeded = tail.size() - throttled;
        double goodput = spanSeconds > 0 ? succeeded / spanSeconds : 0;
        double throttleRate = (double) throttled / tail.size();
        return new Metrics(tail.size(), throttled, goodput, throttleRate);
    }

    // -- Server models -------------------------------------------------------

    /** A sliding-window limiter: at most {@code limit} requests in any trailing {@code window}. */
    static ServerModel slidingWindow(int limit, long windowNanos, long latencyNanos,
                                     boolean emitRetryAfter) {
        return new ServerModel() {
            private final ArrayDeque<Long> hits = new ArrayDeque<>();

            @Override
            public Decision arrival(long now) {
                while (!hits.isEmpty() && hits.peekFirst() <= now - windowNanos) {
                    hits.pollFirst();
                }
                if (hits.size() >= limit) {
                    long retryAfterMs = emitRetryAfter
                        ? TimeUnit.NANOSECONDS.toMillis(hits.peekFirst() + windowNanos - now)
                        : 0;
                    return new Decision(true, Math.max(0, retryAfterMs), latencyNanos);
                }
                hits.addLast(now);
                return new Decision(false, 0, latencyNanos);
            }
        };
    }

    /** A fixed-window limiter: counter resets on each window boundary. */
    static ServerModel fixedWindow(int limit, long windowNanos, long latencyNanos,
                                   boolean emitRetryAfter) {
        return new ServerModel() {
            private long windowStart = Long.MIN_VALUE;
            private int count;

            @Override
            public Decision arrival(long now) {
                if (windowStart == Long.MIN_VALUE || now - windowStart >= windowNanos) {
                    windowStart = now;
                    count = 0;
                }
                if (count >= limit) {
                    long retryAfterMs = emitRetryAfter
                        ? TimeUnit.NANOSECONDS.toMillis(windowStart + windowNanos - now)
                        : 0;
                    return new Decision(true, Math.max(0, retryAfterMs), latencyNanos);
                }
                count++;
                return new Decision(false, 0, latencyNanos);
            }
        };
    }

    /** A leaky/token-bucket limiter refilling at {@code ratePerSecond} with a burst allowance. */
    static ServerModel tokenBucket(double ratePerSecond, double burst, long latencyNanos) {
        return new ServerModel() {
            private double tokens = burst;
            private long last = Long.MIN_VALUE;

            @Override
            public Decision arrival(long now) {
                if (last != Long.MIN_VALUE) {
                    double elapsed = (now - last) / 1_000_000_000.0;
                    tokens = Math.min(burst, tokens + elapsed * ratePerSecond);
                }
                last = now;
                if (tokens >= 1.0) {
                    tokens -= 1.0;
                    return new Decision(false, 0, latencyNanos);
                }
                return new Decision(true, 0, latencyNanos);
            }
        };
    }

    /** Never throttles. */
    static ServerModel unlimited(long latencyNanos) {
        return now -> new Decision(false, 0, latencyNanos);
    }

    /** Delegates to {@code before} until {@code switchAtNanos}, then to {@code after}. */
    static ServerModel switching(ServerModel before, ServerModel after, long switchAtNanos) {
        return now -> (now < switchAtNanos ? before : after).arrival(now);
    }

    /** Delegates to {@code before} for the first {@code switchAfterArrivals} arrivals, then {@code after}. */
    static ServerModel switchingByCount(ServerModel before, ServerModel after, int switchAfterArrivals) {
        return new ServerModel() {
            private int arrivals;

            @Override
            public Decision arrival(long now) {
                return (arrivals++ < switchAfterArrivals ? before : after).arrival(now);
            }
        };
    }
}
