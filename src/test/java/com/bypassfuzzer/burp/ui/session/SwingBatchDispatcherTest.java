package com.bypassfuzzer.burp.ui.session;

import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SwingBatchDispatcherTest {

    @Test
    void deliversBatchesOnTheSwingThreadAndSignalsAfterDrain() throws Exception {
        List<Integer> delivered = Collections.synchronizedList(new ArrayList<>());
        AtomicBoolean deliveredOnSwingThread = new AtomicBoolean(true);
        CountDownLatch drained = new CountDownLatch(1);
        SwingBatchDispatcher<Integer> dispatcher = new SwingBatchDispatcher<>(8, 3, batch -> {
            deliveredOnSwingThread.compareAndSet(true, SwingUtilities.isEventDispatchThread());
            delivered.addAll(batch);
        });
        try {
            for (int value = 0; value < 8; value++) assertTrue(dispatcher.submit(value));
            dispatcher.afterDrained(drained::countDown);

            assertTrue(drained.await(2, TimeUnit.SECONDS));
            assertTrue(deliveredOnSwingThread.get());
            assertEquals(List.of(0, 1, 2, 3, 4, 5, 6, 7), delivered);
        } finally {
            dispatcher.close();
        }
    }

    @Test
    void blocksProducersInsteadOfGrowingPastCapacity() throws Exception {
        CountDownLatch consumerEntered = new CountDownLatch(1);
        CountDownLatch releaseConsumer = new CountDownLatch(1);
        CountDownLatch fourthSubmitted = new CountDownLatch(1);
        SwingBatchDispatcher<Integer> dispatcher = new SwingBatchDispatcher<>(2, 1, batch -> {
            consumerEntered.countDown();
            try {
                releaseConsumer.await(2, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        Thread producer = null;
        try {
            assertTrue(dispatcher.submit(1));
            assertTrue(consumerEntered.await(2, TimeUnit.SECONDS));
            assertTrue(dispatcher.submit(2));
            assertTrue(dispatcher.submit(3));
            producer = new Thread(() -> {
                if (dispatcher.submit(4)) fourthSubmitted.countDown();
            });
            producer.start();

            assertFalse(fourthSubmitted.await(150, TimeUnit.MILLISECONDS));
            assertEquals(2, dispatcher.pendingCount());

            releaseConsumer.countDown();
            assertTrue(fourthSubmitted.await(2, TimeUnit.SECONDS));
        } finally {
            releaseConsumer.countDown();
            dispatcher.close();
            if (producer != null) producer.join(2_000);
        }
    }
}
