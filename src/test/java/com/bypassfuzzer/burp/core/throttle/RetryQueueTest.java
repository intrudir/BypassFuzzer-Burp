package com.bypassfuzzer.burp.core.throttle;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RetryQueueTest {

    @Test
    void boundedQueueReportsRejectedAutomaticRetriesWithoutCorruptingFifoState() {
        RetryQueue<String> queue = new RetryQueue<>(2);

        assertTrue(queue.enqueue("one"));
        assertTrue(queue.enqueue("two"));
        assertFalse(queue.enqueue("three"));

        assertEquals(2, queue.size());
        assertEquals(1, queue.rejectedCount());
        assertEquals(java.util.List.of("one", "two"), queue.drain(10));
        assertTrue(queue.isEmpty());
    }
}
