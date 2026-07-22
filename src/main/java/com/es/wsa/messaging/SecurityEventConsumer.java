package com.es.wsa.messaging;

import com.es.wsa.config.AsyncConfig;
import com.es.wsa.domain.SecurityEvent;
import com.es.wsa.enrichment.EventProcessor;
import com.es.wsa.storage.EventStorageService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

/**
 * Asynchronous consumer that bridges the internal event bus to the Enrichment stage.
 *
 * <h2>Architectural intent</h2>
 * This component is the <strong>entry point of the (future) Enrichment Service</strong>.
 * Today it consumes {@link SecurityEventMessage}s from Spring's in-JVM event bus via
 * {@link EventListener @EventListener}, running on a dedicated bounded executor
 * ({@link Async @Async}) so enrichment never blocks the HTTP ingestion thread — the API
 * returns {@code 201} as soon as the event is handed to the bus.
 *
 * <p>It is intentionally written to be <strong>indistinguishable in shape from a Kafka
 * listener</strong>: replacing {@code @EventListener} + {@code @Async} with
 * {@code @KafkaListener(topics = "wsa.events.ingested")} and moving this class into a
 * separate deployable would complete the migration to two microservices — the body
 * (unwrap envelope → {@link EventProcessor#process(SecurityEvent)}) stays identical.
 *
 * <h2>Error handling</h2>
 * Because this runs asynchronously, exceptions cannot propagate to a caller. Any
 * enrichment <em>or storage</em> failure is caught and logged so that:
 * <ul>
 *   <li>the consumer thread is never killed, and</li>
 *   <li>one poison event never blocks or drops subsequent events.</li>
 * </ul>
 * In the Kafka target this is where a retry/dead-letter-topic policy would live; here we
 * log-and-continue, which is the correct at-most-once behaviour for an in-memory bus.
 */
@Component
public class SecurityEventConsumer {

    private static final Logger log = LoggerFactory.getLogger(SecurityEventConsumer.class);

    private final EventProcessor eventProcessor;
    private final EventStorageService storageService;

    public SecurityEventConsumer(EventProcessor eventProcessor, EventStorageService storageService) {
        this.eventProcessor = eventProcessor;
        this.storageService = storageService;
    }

    /**
     * Consumes an ingested event, drives enrichment, then persists the enriched event to
     * long-term storage. Runs on the {@link AsyncConfig#ENRICHMENT_EXECUTOR enrichment
     * executor}.
     *
     * @param message the internal message envelope carrying the validated event
     */
    @Async(AsyncConfig.ENRICHMENT_EXECUTOR)
    @EventListener
    public void onSecurityEvent(SecurityEventMessage message) {
        SecurityEvent event = message.event();
        log.info("Event {} consumed from internal queue and starting enrichment on thread {}",
                event.eventId(), Thread.currentThread().getName());
        try {
            SecurityEvent enriched = eventProcessor.process(event);
            log.info("Event {} enriched: attackType='{}', threatScore={}",
                    enriched.eventId(), enriched.attackType(), enriched.threatScore());

            storageService.save(enriched);
            log.info("Event {} successfully enriched and indexed to Elasticsearch", enriched.eventId());
        } catch (Exception ex) {
            // Graceful degradation: never let a single failure (enrichment or storage)
            // crash the consumer or block the pipeline. A real Enrichment Service would
            // route to a DLT here.
            log.error("Processing failed for event {}; skipping. Cause: {}",
                    event.eventId(), ex.getMessage(), ex);
        }
    }
}
