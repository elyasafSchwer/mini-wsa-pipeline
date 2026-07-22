package com.es.wsa.messaging;

import com.es.wsa.domain.SecurityEvent;
import com.es.wsa.publisher.EventPublisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

/**
 * {@link EventPublisher} backed by Spring's in-JVM {@link ApplicationEventPublisher}.
 *
 * <h2>Architectural intent</h2>
 * This implementation decouples the Ingestion API from the Enrichment stage using an
 * <strong>in-memory publish/subscribe bus</strong>, so the take-home runs with zero
 * external infrastructure for the reviewer (no Kafka broker to stand up). The design is,
 * however, deliberately shaped for a <strong>drop-in migration to Kafka and a split into
 * two microservices</strong>:
 * <ul>
 *   <li>The Ingestion side depends only on the transport-agnostic {@link EventPublisher}
 *       interface — it has <em>zero</em> knowledge that Spring Events (or, later, Kafka)
 *       are the underlying transport. Swapping this bean for a {@code KafkaPublisherImpl}
 *       is a one-line change (move {@link Primary @Primary}), with no change to the
 *       controller.</li>
 *   <li>Messages travel as a {@link SecurityEventMessage} envelope — the direct analogue
 *       of a Kafka record value — rather than the raw domain object.</li>
 *   <li>{@link SecurityEventMessage#partitionKey()} already names the future Kafka
 *       partition key (client IP), preserving per-IP ordering once partitioned.</li>
 * </ul>
 * In the target topology the {@code publish} call becomes a {@code KafkaTemplate.send()}
 * to an {@code wsa.events.ingested} topic, and the consumer becomes a
 * {@code @KafkaListener} in a separate Enrichment Service — the interface seam here is
 * what makes that migration mechanical rather than invasive.
 *
 * <p>Marked {@link Primary @Primary} so it is the {@link EventPublisher} the ingestion
 * controller autowires, in preference to the Module 1 console stub which is retained as a
 * reference/fallback implementation.
 */
@Component
@Primary
public class SpringEventPublisherImpl implements EventPublisher {

    private static final Logger log = LoggerFactory.getLogger(SpringEventPublisherImpl.class);

    private final ApplicationEventPublisher applicationEventPublisher;

    public SpringEventPublisherImpl(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }

    @Override
    public void publish(SecurityEvent event) {
        SecurityEventMessage message = new SecurityEventMessage(event);
        applicationEventPublisher.publishEvent(message);
        log.info("Event {} published to internal queue (partitionKey={})",
                event.eventId(), message.partitionKey());
    }
}
