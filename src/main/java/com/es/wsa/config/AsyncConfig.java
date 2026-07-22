package com.es.wsa.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * Enables asynchronous event handling and provides the executor that backs the enrichment
 * consumer.
 *
 * <p>The consumer runs on a dedicated, bounded {@link ThreadPoolTaskExecutor} rather than
 * Spring's default {@code SimpleAsyncTaskExecutor} (which spawns an unbounded number of
 * threads). A bounded pool with an explicit queue and a {@link ThreadPoolExecutor.CallerRunsPolicy
 * caller-runs} rejection policy gives production-sensible back-pressure: if enrichment
 * falls behind, the publishing thread absorbs the work instead of the queue growing
 * without limit. This mirrors the bounded-consumer model a Kafka consumer group would
 * provide in the target architecture.
 */
@Configuration
@EnableAsync
public class AsyncConfig {

    private static final Logger log = LoggerFactory.getLogger(AsyncConfig.class);

    /** Bean name referenced by {@code @Async} on the enrichment consumer. */
    public static final String ENRICHMENT_EXECUTOR = "enrichmentTaskExecutor";

    @Bean(name = ENRICHMENT_EXECUTOR)
    public Executor enrichmentTaskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(4);
        executor.setMaxPoolSize(8);
        executor.setQueueCapacity(500);
        executor.setThreadNamePrefix("enrichment-");
        // Back-pressure: when the pool and queue are saturated, run on the caller thread
        // rather than dropping events or growing memory unbounded.
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        // Let in-flight enrichment finish on shutdown instead of being interrupted.
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(30);
        executor.initialize();
        log.info("Initialised enrichment executor '{}' (core={}, max={}, queue={})",
                ENRICHMENT_EXECUTOR, executor.getCorePoolSize(), executor.getMaxPoolSize(), 500);
        return executor;
    }
}
