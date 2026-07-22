package com.es.wsa.messaging;

import com.es.wsa.domain.SecurityEvent;

/**
 * Internal message envelope carrying a validated {@link SecurityEvent} across the
 * ingestion → enrichment boundary.
 *
 * <p>This wrapper is deliberately distinct from the domain object so the messaging layer
 * has its own stable type. It is the in-memory analogue of a Kafka record: today it is
 * published on Spring's {@code ApplicationEventPublisher} and consumed by an
 * {@code @EventListener}; in the target architecture the same envelope would be
 * serialized as the value of a Kafka {@code ProducerRecord} on an
 * {@code wsa.events.ingested} topic and deserialized by a {@code @KafkaListener} in a
 * separate Enrichment Service.
 *
 * <p>Keeping a dedicated envelope (rather than publishing the raw {@link SecurityEvent})
 * leaves a natural home for future transport metadata — partition key, schema version,
 * trace/correlation ids, produced-at timestamp — without touching the domain model.
 *
 * @param event the validated, {@code receivedAt}-stamped event to be enriched
 */
public record SecurityEventMessage(SecurityEvent event) {

    public SecurityEventMessage {
        if (event == null) {
            throw new IllegalArgumentException("event must not be null");
        }
    }

    /**
     * @return the natural partition/routing key for this message — the client IP — so
     * that a future Kafka migration keeps all events for one IP on the same partition
     * (preserving per-IP ordering for the rate tracker). Purely informational today.
     */
    public String partitionKey() {
        return event.clientIp();
    }
}
