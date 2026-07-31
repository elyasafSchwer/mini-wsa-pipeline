package com.es.wsa.config;

import com.es.wsa.messaging.KeyedExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Provides the executor that backs the enrichment consumer.
 *
 * <p>Enrichment runs on a {@link KeyedExecutor}: a fixed set of single-thread lanes keyed by
 * {@code clientIp}. This gives <strong>per-IP ordering with cross-IP parallelism</strong> —
 * all events from one IP are enriched serially in ingestion order (so the repeat-offender
 * sliding-window count is observed deterministically), while different IPs process in
 * parallel. It is the in-JVM analogue of "one consumer thread per Kafka partition", keyed on
 * the same {@code SecurityEventMessage.partitionKey()} a Kafka producer would use.
 *
 * <p>Each lane is bounded with a caller-runs rejection policy, so a saturated lane applies
 * back-pressure (the ingestion thread absorbs the work) instead of dropping events or growing
 * memory without limit — the same production posture as a bounded Kafka consumer.
 *
 * <p>{@link EnableAsync @EnableAsync} remains enabled for any other {@code @Async} use; the
 * enrichment path itself no longer relies on {@code @Async} method dispatch — it routes to a
 * lane explicitly so it can pin work by key.
 */
@Configuration
@EnableAsync
@EnableScheduling
public class AsyncConfig {

    private static final Logger log = LoggerFactory.getLogger(AsyncConfig.class);

    /** Number of enrichment lanes (parallelism ceiling; matches the prior pool's max size). */
    private static final int ENRICHMENT_LANES = 8;
    /** Bounded queue depth per lane before back-pressure (caller-runs) engages. */
    private static final int LANE_QUEUE_CAPACITY = 500;

    /**
     * The keyed executor backing enrichment. {@code destroyMethod = "shutdown"} lets
     * in-flight enrichment finish on application shutdown.
     */
    @Bean(destroyMethod = "shutdown")
    public KeyedExecutor enrichmentExecutor() {
        KeyedExecutor executor = new KeyedExecutor(ENRICHMENT_LANES, LANE_QUEUE_CAPACITY, "enrichment-");
        log.info("Enrichment executor ready ({} lanes, per-IP ordering)", executor.laneCount());
        return executor;
    }
}
