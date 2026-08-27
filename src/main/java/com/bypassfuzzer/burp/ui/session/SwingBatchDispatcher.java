package com.bypassfuzzer.burp.ui.session;

import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/** Bounded, backpressured delivery from scan workers to the Swing event thread. */
final class SwingBatchDispatcher<T> implements AutoCloseable {
    static final int DEFAULT_CAPACITY = 512;
    static final int DEFAULT_BATCH_SIZE = 128;

    private final ArrayBlockingQueue<T> pending;
    private final int batchSize;
    private final Consumer<List<T>> batchConsumer;
    private final ConcurrentLinkedQueue<Runnable> drainedCallbacks = new ConcurrentLinkedQueue<>();
    private final AtomicBoolean drainScheduled = new AtomicBoolean();
    private final AtomicBoolean closed = new AtomicBoolean();

    SwingBatchDispatcher(Consumer<List<T>> batchConsumer) {
        this(DEFAULT_CAPACITY, DEFAULT_BATCH_SIZE, batchConsumer);
    }

    SwingBatchDispatcher(int capacity, int batchSize, Consumer<List<T>> batchConsumer) {
        this.pending = new ArrayBlockingQueue<>(Math.max(1, capacity));
        this.batchSize = Math.max(1, Math.min(batchSize, capacity));
        this.batchConsumer = batchConsumer;
    }

    boolean submit(T item) {
        if (item == null || closed.get()) return false;
        scheduleDrain();
        while (!closed.get()) {
            try {
                if (pending.offer(item, 100, TimeUnit.MILLISECONDS)) {
                    scheduleDrain();
                    return true;
                }
                scheduleDrain();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }

    void afterDrained(Runnable callback) {
        if (callback == null || closed.get()) return;
        drainedCallbacks.add(callback);
        scheduleDrain();
    }

    void clear() {
        pending.clear();
        drainedCallbacks.clear();
    }

    int pendingCount() {
        return pending.size();
    }

    private void scheduleDrain() {
        if (!closed.get() && drainScheduled.compareAndSet(false, true)) {
            SwingUtilities.invokeLater(this::drainOneBatch);
        }
    }

    private void drainOneBatch() {
        if (closed.get()) {
            drainScheduled.set(false);
            return;
        }
        List<T> batch = new ArrayList<>(batchSize);
        pending.drainTo(batch, batchSize);
        try {
            if (!batch.isEmpty()) batchConsumer.accept(List.copyOf(batch));
        } finally {
            drainScheduled.set(false);
            if (!pending.isEmpty()) {
                scheduleDrain();
            } else {
                Runnable callback;
                while ((callback = drainedCallbacks.poll()) != null) callback.run();
                if (!pending.isEmpty() || !drainedCallbacks.isEmpty()) scheduleDrain();
            }
        }
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) clear();
    }
}
