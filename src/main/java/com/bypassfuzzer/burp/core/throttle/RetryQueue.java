package com.bypassfuzzer.burp.core.throttle;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A single bounded FIFO for requests that were throttled and should be retried, replacing the
 * separate ad-hoc retry queues that used to live in the rate limiter, the sweep engine, and the
 * results workspace.
 *
 * @param <T> the queued retry item (e.g. a throttled request plus its presentation context)
 */
public final class RetryQueue<T> {

    /** Upper bound so a pathological run cannot exhaust memory with deferred retries. */
    public static final int DEFAULT_MAX_SIZE = 5000;

    private final ConcurrentLinkedQueue<T> queue = new ConcurrentLinkedQueue<>();
    private final int maxSize;
    private final AtomicInteger size = new AtomicInteger();
    private final AtomicLong rejected = new AtomicLong();

    public RetryQueue() {
        this(DEFAULT_MAX_SIZE);
    }

    public RetryQueue(int maxSize) {
        this.maxSize = Math.max(1, maxSize);
    }

    /**
     * Adds an item when capacity is available. A rejected automatic retry remains observable to the
     * caller, which can retain the corresponding HTTP result for a manual retry instead of silently
     * losing coverage.
     */
    public boolean enqueue(T item) {
        if (item == null) {
            return false;
        }
        while (true) {
            int current = size.get();
            if (current >= maxSize) {
                rejected.incrementAndGet();
                return false;
            }
            if (size.compareAndSet(current, current + 1)) {
                queue.add(item);
                return true;
            }
        }
    }

    /** Removes and returns up to {@code maxCount} items in FIFO order. */
    public List<T> drain(int maxCount) {
        List<T> drained = new ArrayList<>();
        for (int i = 0; i < maxCount; i++) {
            T item = queue.poll();
            if (item == null) {
                break;
            }
            size.decrementAndGet();
            drained.add(item);
        }
        return drained;
    }

    public int size() {
        return size.get();
    }

    public boolean isEmpty() {
        return size.get() == 0;
    }

    /** Number of attempts that could not enter automatic retry scheduling. */
    public long rejectedCount() {
        return rejected.get();
    }
}
