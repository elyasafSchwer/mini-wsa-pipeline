package com.es.wsa.messaging;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link KeyedExecutor}: same-key tasks run serially in submission order on a
 * single lane; different keys can run on different lanes (parallelism); and a null/blank key
 * routes without error.
 */
class KeyedExecutorTest {

    private KeyedExecutor executor;

    @AfterEach
    void tearDown() {
        if (executor != null) {
            executor.shutdown();
        }
    }

    @Test
    void sameKeyRunsSeriallyInSubmissionOrderOnOneThread() throws InterruptedException {
        executor = new KeyedExecutor(8, 1000, "test-");

        int tasks = 200;
        List<Integer> order = new CopyOnWriteArrayList<>();
        ConcurrentHashMap<String, Boolean> threads = new ConcurrentHashMap<>();
        CountDownLatch done = new CountDownLatch(tasks);

        for (int i = 0; i < tasks; i++) {
            int seq = i;
            executor.execute("203.0.113.7", () -> {
                order.add(seq);
                threads.put(Thread.currentThread().getName(), Boolean.TRUE);
                done.countDown();
            });
        }

        assertThat(done.await(5, TimeUnit.SECONDS)).isTrue();
        // Strict FIFO: 0,1,2,...,199 — no reordering within a key.
        assertThat(order).containsExactlyElementsOf(
                java.util.stream.IntStream.range(0, tasks).boxed().toList());
        // All ran on exactly one lane thread.
        assertThat(threads.keySet()).hasSize(1);
    }

    @Test
    void sameKeyStaysOrderedAndSingleThreadedUnderQueueSaturation() throws InterruptedException {
        // Regression test for the CallerRunsPolicy bug: a tiny queue + slow tasks force the
        // rejection path. The old policy ran rejected tasks on the *caller* thread, so
        // same-key tasks executed concurrently and out of order. With blocking back-pressure
        // the caller waits instead, so ordering + single-thread must hold even when saturated.
        executor = new KeyedExecutor(4, 2, "sat-");   // queue depth of just 2

        int tasks = 100;
        List<Integer> order = new CopyOnWriteArrayList<>();
        ConcurrentHashMap<String, Boolean> threads = new ConcurrentHashMap<>();
        CountDownLatch done = new CountDownLatch(tasks);

        // Submit faster than the lane can drain (each task sleeps), guaranteeing the bounded
        // queue fills and the rejection/back-pressure path is exercised.
        for (int i = 0; i < tasks; i++) {
            int seq = i;
            executor.execute("1.2.3.4", () -> {
                order.add(seq);
                threads.put(Thread.currentThread().getName(), Boolean.TRUE);
                try {
                    Thread.sleep(2);   // simulate a slow enrichment/ES write
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                done.countDown();
            });
        }

        assertThat(done.await(15, TimeUnit.SECONDS)).isTrue();
        // Even under saturation: strict FIFO and a single executing thread.
        assertThat(order).containsExactlyElementsOf(
                java.util.stream.IntStream.range(0, tasks).boxed().toList());
        assertThat(threads.keySet())
                .as("all same-key tasks must run on one lane thread, even when the queue saturates")
                .hasSize(1);
    }

    @Test
    void differentKeysCanUseDifferentLanes() throws InterruptedException {
        executor = new KeyedExecutor(8, 1000, "test-");

        // Choose keys that hash to distinct lanes so this is deterministic.
        List<String> keys = distinctLaneKeys(4);
        ConcurrentHashMap<String, Boolean> threads = new ConcurrentHashMap<>();
        CountDownLatch done = new CountDownLatch(keys.size());

        for (String key : keys) {
            executor.execute(key, () -> {
                threads.put(Thread.currentThread().getName(), Boolean.TRUE);
                done.countDown();
            });
        }

        assertThat(done.await(5, TimeUnit.SECONDS)).isTrue();
        // Keys on distinct lanes -> distinct threads.
        assertThat(threads.keySet()).hasSize(keys.size());
    }

    @Test
    void nullAndBlankKeyRouteToLaneZeroWithoutError() {
        executor = new KeyedExecutor(4, 10, "test-");
        assertThat(executor.laneFor(null)).isZero();
        assertThat(executor.laneFor("   ")).isZero();

        AtomicInteger ran = new AtomicInteger();
        executor.execute(null, ran::incrementAndGet);
        executor.execute("", ran::incrementAndGet);
        // No exception; both accepted (they run on lane 0).
        assertThat(ran.get()).isBetween(0, 2); // may not have run yet; the point is no throw
    }

    @Test
    void laneForIsStableAndInRange() {
        executor = new KeyedExecutor(8, 10, "test-");
        int a = executor.laneFor("203.0.113.7");
        int b = executor.laneFor("203.0.113.7");
        assertThat(a).isEqualTo(b).isBetween(0, 7);
    }

    /** Finds {@code n} keys that each hash to a different lane (for an 8-lane executor). */
    private List<String> distinctLaneKeys(int n) {
        List<String> keys = new java.util.ArrayList<>();
        java.util.Set<Integer> lanes = new java.util.HashSet<>();
        int i = 0;
        while (keys.size() < n) {
            String candidate = "10.0.0." + i++;
            int lane = executor.laneFor(candidate);
            if (lanes.add(lane)) {
                keys.add(candidate);
            }
        }
        return keys;
    }
}
