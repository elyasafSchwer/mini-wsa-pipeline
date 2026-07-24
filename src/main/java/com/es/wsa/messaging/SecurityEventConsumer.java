package com.es.wsa.messaging;

import com.es.wsa.domain.SecurityEvent;
import com.es.wsa.enrichment.EventProcessor;
import com.es.wsa.storage.EventStorageService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Consumer that bridges the internal event bus to the Enrichment stage.
 *
 * <h2>Architectural intent</h2>
 * This component is the <strong>entry point of the (future) Enrichment Service</strong>.
 * Today it consumes {@link SecurityEventMessage}s from Spring's in-JVM event bus via
 * {@link EventListener @EventListener} and dispatches each to a {@link KeyedExecutor} lane
 * keyed by {@code clientIp}, so enrichment never blocks the HTTP ingestion thread — the API
 * returns {@code 201} as soon as the event is routed to a lane.
 *
 * <h2>Per-IP ordering</h2>
 * Events are routed by {@link SecurityEventMessage#partitionKey()} (client IP) to a fixed
 * lane, so all events from one IP are enriched <strong>serially, in ingestion order</strong>,
 * while different IPs process in parallel. This keeps the repeat-offender rate-tracker count
 * deterministic (no same-IP race into Redis) and mirrors Kafka's partition-by-key ordering:
 * replacing {@code @EventListener} + {@link KeyedExecutor} with
 * {@code @KafkaListener(topics = "wsa.events.ingested")} (partitioned on the same key) and
 * moving this class into a separate deployable completes the migration — the body
 * ({@link #process(SecurityEventMessage)}) stays identical.
 *
 * <h2>Error handling</h2>
 * Enrichment runs off the caller thread, so exceptions cannot propagate to a caller. Any
 * enrichment <em>or storage</em> failure is caught and logged so that the lane thread is
 * never killed and one poison event never blocks subsequent events. In the Kafka target this
 * is where a retry/dead-letter-topic policy would live; here we log-and-continue.
 */
@Component
public class SecurityEventConsumer {

    private static final Logger log = LoggerFactory.getLogger(SecurityEventConsumer.class);

    private final EventProcessor eventProcessor;
    private final EventStorageService storageService;
    private final KeyedExecutor enrichmentExecutor;

    public SecurityEventConsumer(EventProcessor eventProcessor,
                                 EventStorageService storageService,
                                 KeyedExecutor enrichmentExecutor) {
        this.eventProcessor = eventProcessor;
        this.storageService = storageService;
        this.enrichmentExecutor = enrichmentExecutor;
    }

    /**
     * Consumes an ingested event and routes it to the enrichment lane owning its client IP.
     * Returns as soon as the work is enqueued (the publishing thread is not blocked by
     * enrichment), preserving fast ingestion responses.
     *
     * @param message the internal message envelope carrying the validated event
     */
    @EventListener
    public void onSecurityEvent(SecurityEventMessage message) {
        // Route by client IP so a single IP's events are enriched in order on one lane,
        // while different IPs run in parallel across lanes.
        enrichmentExecutor.execute(message.partitionKey(), () -> process(message));
    }

    /**
     * Enriches then persists a single event. Runs on the event's enrichment lane. Any
     * failure is swallowed (logged) so the lane survives and later events are unaffected.
     *
     * @param message the message envelope to process
     */
    void process(SecurityEventMessage message) {
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
            // crash the lane or block the pipeline. A real Enrichment Service would route
            // to a DLT here.
            log.error("Processing failed for event {}; skipping. Cause: {}",
                    event.eventId(), ex.getMessage(), ex);
        }
    }
}
