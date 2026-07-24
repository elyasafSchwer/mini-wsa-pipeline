package com.es.wsa.messaging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Routes tasks to a fixed set of single-thread "lanes" by a routing key, giving
 * <strong>per-key ordering with cross-key parallelism</strong>: all tasks for the same key
 * run serially in submission order (one dedicated thread), while different keys run in
 * parallel across lanes.
 *
 * <p>This is the in-JVM analogue of Kafka's partition-by-key model — "one consumer thread
 * per partition". The enrichment consumer uses it with {@code clientIp} as the key so a
 * single IP's events are enriched strictly in ingestion order (keeping the repeat-offender
 * sliding-window count deterministic), while traffic from different IPs still processes
 * concurrently.
 *
 * <h2>Back-pressure without breaking ordering</h2>
 * Each lane is a single-thread {@link ThreadPoolExecutor} with a <em>bounded</em> queue. The
 * critical subtlety: the rejection policy must never run a task on any thread other than the
 * lane's own, or same-key tasks would execute concurrently and lose their order. So when a
 * lane's queue is full, the submitting thread <strong>blocks</strong> until space frees
 * ({@code queue.put}) rather than running the task itself (which a
 * {@code CallerRunsPolicy} would do). Back-pressure is therefore "the caller waits", which
 * bounds memory <em>and</em> preserves strict per-lane FIFO.
 *
 * <p><strong>Trade-offs:</strong>
 * <ul>
 *   <li>Ordering is <em>per key</em>, not global — different keys interleave arbitrarily.</li>
 *   <li>Two distinct keys may hash to the same lane and then serialize relative to each
 *       other. Harmless: only <em>same-key</em> ordering is promised.</li>
 *   <li>A slow/stuck key blocks only its own lane; a saturated lane blocks its submitters
 *       (back-pressure), never spills work onto other threads.</li>
 * </ul>
 */
public class KeyedExecutor {

    private static final Logger log = LoggerFactory.getLogger(KeyedExecutor.class);

    private final List<ThreadPoolExecutor> lanes;

    /**
     * @param laneCount     number of single-thread lanes (parallelism ceiling)
     * @param queueCapacity bounded queue depth per lane; a full queue blocks the submitter
     * @param threadPrefix  thread-name prefix (lane index is appended)
     */
    public KeyedExecutor(int laneCount, int queueCapacity, String threadPrefix) {
        if (laneCount < 1) {
            throw new IllegalArgumentException("laneCount must be at least 1");
        }
        this.lanes = new ArrayList<>(laneCount);
        for (int i = 0; i < laneCount; i++) {
            lanes.add(newLane(queueCapacity, threadPrefix + i + "-"));
        }
        log.info("Initialised KeyedExecutor with {} lane(s) (queueCapacity={} each, blocking back-pressure)",
                laneCount, queueCapacity);
    }

    /**
     * A single-thread executor whose bounded queue applies blocking back-pressure: when the
     * queue is full, the rejection handler {@code put}s the task (blocking the caller) so the
     * task still ends up on this one lane thread — never run elsewhere — preserving FIFO.
     */
    private static ThreadPoolExecutor newLane(int queueCapacity, String threadPrefix) {
        ThreadFactory threadFactory = new ThreadFactory() {
            private final AtomicInteger n = new AtomicInteger();
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r, threadPrefix + n.incrementAndGet());
                t.setDaemon(true);
                return t;
            }
        };
        return new ThreadPoolExecutor(
                1, 1,                       // exactly one thread => strict FIFO within the lane
                0L, TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(queueCapacity),
                threadFactory,
                (task, executor) -> {
                    // Blocking back-pressure: wait for queue space instead of running the
                    // task on the caller thread (which would break per-lane ordering).
                    if (executor.isShutdown()) {
                        throw new RejectedExecutionException("KeyedExecutor lane is shut down");
                    }
                    try {
                        executor.getQueue().put(task);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new RejectedExecutionException("Interrupted while enqueuing task", e);
                    }
                });
    }

    /**
     * Submits {@code task} to the lane owning {@code key}. Tasks sharing a key are executed
     * in submission order on the same thread.
     *
     * @param key  the routing key; {@code null}/blank routes to lane 0 deterministically
     * @param task the work to run
     */
    public void execute(String key, Runnable task) {
        lanes.get(laneFor(key)).execute(task);
    }

    /** @return the lane index a key routes to (stable for a given key + lane count). */
    int laneFor(String key) {
        if (key == null || key.isBlank()) {
            return 0;
        }
        // floorMod keeps the index non-negative even when hashCode() is negative.
        return Math.floorMod(key.hashCode(), lanes.size());
    }

    /** @return the number of lanes. */
    public int laneCount() {
        return lanes.size();
    }

    /** Gracefully shuts every lane down, letting in-flight/queued tasks finish. */
    public void shutdown() {
        lanes.forEach(lane -> {
            lane.shutdown();
            try {
                if (!lane.awaitTermination(30, TimeUnit.SECONDS)) {
                    lane.shutdownNow();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                lane.shutdownNow();
            }
        });
    }
}
