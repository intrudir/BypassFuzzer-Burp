package com.bypassfuzzer.core.throttle;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BooleanSupplier;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * Extension-wide admission gate for every physical scan request. It provides a global manual pause,
 * a total in-flight cap, and smooth per-host pacing shared by all scan sessions.
 */
public class GlobalTrafficGovernor<Q> {

    /** Nonblocking local reservation: zero reserves a send; positive values request another check after that delay. */
    public record LocalAdmission(LongSupplier acquire,Runnable release) {
        public LocalAdmission {java.util.Objects.requireNonNull(acquire);java.util.Objects.requireNonNull(release);}
    }

    public record Snapshot(boolean limitsEnabled, boolean paused, int maxInFlight,
                           double maxRequestsPerSecondPerHost, int inFlight,
                           int queued, long admittedRequests) { }

    private static final long CANCELLATION_POLL_NANOS = TimeUnit.MILLISECONDS.toNanos(100);

    private final ReentrantLock lock = new ReentrantLock(true);
    private final Condition stateChanged = lock.newCondition();
    private final Map<String, Long> lastAdmissionNanos = new HashMap<>();
    private final LongSupplier nanoTime;

    private boolean limitsEnabled;
    private boolean paused;
    private int maxInFlight = 10;
    private double maxRequestsPerSecondPerHost = 10.0;
    private int inFlight;
    private int queued;
    private long admittedRequests;

    private final java.util.function.Function<Q, String> hostKey;
    public GlobalTrafficGovernor(java.util.function.Function<Q, String> hostKey) {
        this(hostKey, System::nanoTime);
    }
    public GlobalTrafficGovernor(java.util.function.Function<Q, String> hostKey, LongSupplier nanoTime) {
        this.hostKey = hostKey;
        this.nanoTime = nanoTime == null ? System::nanoTime : nanoTime;
    }

    public void configure(boolean enabled, int newMaxInFlight, double newMaxRatePerHost) {
        lock.lock();
        try {
            limitsEnabled = enabled;
            maxInFlight = Math.max(1, newMaxInFlight);
            maxRequestsPerSecondPerHost = Math.max(0.1, newMaxRatePerHost);
            stateChanged.signalAll();
        } finally {
            lock.unlock();
        }
    }

    public void pause() {
        lock.lock();
        try {
            paused = true;
        } finally {
            lock.unlock();
        }
    }

    public void resume() {
        lock.lock();
        try {
            paused = false;
            stateChanged.signalAll();
        } finally {
            lock.unlock();
        }
    }

    public boolean isPaused() {
        lock.lock();
        try {
            return paused;
        } finally {
            lock.unlock();
        }
    }

    public Snapshot snapshot() {
        lock.lock();
        try {
            return new Snapshot(limitsEnabled, paused, maxInFlight,
                maxRequestsPerSecondPerHost, inFlight, queued, admittedRequests);
        } finally {
            lock.unlock();
        }
    }

    /** Executes one physical HTTP attempt after acquiring shared and optional local admission together. */
    public <T> T execute(Q request,Supplier<T> sender,BooleanSupplier continuing) {
        return execute(request,sender,continuing,null);
    }
    public <T> T execute(Q request,Supplier<T> sender,BooleanSupplier continuing,LocalAdmission local) {
        if(sender==null || !acquire(request,continuing,local))return null;
        try{return sender.get();}
        finally {
            try{if(local!=null)local.release().run();}
            finally{release();}
        }
    }

    private boolean acquire(Q request,BooleanSupplier shouldContinue,LocalAdmission local) {
        String hostKey = this.hostKey.apply(request);
        lock.lock();
        queued++;
        try {
            while (true) {
                // A scan's predicate may wait on its local pause controller. Never invoke it while
                // holding the global lock or one locally-paused tab could block all traffic controls.
                lock.unlock();
                boolean continueAllowed;
                try {
                    continueAllowed = !Thread.currentThread().isInterrupted()
                        && (shouldContinue == null || shouldContinue.getAsBoolean());
                } finally {
                    lock.lock();
                }
                if (!continueAllowed) {
                    return false;
                }

                long now = nanoTime.getAsLong();
                long rateWaitNanos = limitsEnabled ? rateWaitNanos(hostKey, now) : 0L;
                boolean concurrencyAvailable = !limitsEnabled || inFlight < maxInFlight;
                long localWaitNanos=0;
                if(!paused && concurrencyAvailable && rateWaitNanos<=0L)
                    localWaitNanos=local==null ? 0 : local.acquire().getAsLong();
                if (!paused && concurrencyAvailable && rateWaitNanos <= 0L && localWaitNanos==0) {
                    inFlight++;
                    admittedRequests++;
                    if (limitsEnabled) {
                        lastAdmissionNanos.put(hostKey, now);
                    }
                    return true;
                }

                long waitNanos = CANCELLATION_POLL_NANOS;
                if (!paused && concurrencyAvailable && rateWaitNanos > 0L) {
                    waitNanos = Math.min(waitNanos,rateWaitNanos);
                }else if(localWaitNanos>0L) {
                    waitNanos=Math.min(waitNanos,localWaitNanos);
                }
                try {
                    stateChanged.awaitNanos(Math.max(1L, waitNanos));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
        } finally {
            queued--;
            lock.unlock();
        }
    }

    private long rateWaitNanos(String hostKey, long now) {
        Long lastAdmission = lastAdmissionNanos.get(hostKey);
        if (lastAdmission == null) {
            return 0L;
        }
        long interval = Math.max(1L,
            (long) (TimeUnit.SECONDS.toNanos(1) / maxRequestsPerSecondPerHost));
        return lastAdmission + interval - now;
    }

    private void release() {
        lock.lock();
        try {
            inFlight = Math.max(0, inFlight - 1);
            stateChanged.signalAll();
        } finally {
            lock.unlock();
        }
    }
}
