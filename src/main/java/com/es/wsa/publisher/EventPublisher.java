package com.es.wsa.publisher;

import com.es.wsa.domain.SecurityEvent;

/**
 * Abstraction over the destination that validated {@link SecurityEvent}s are handed off
 * to (a message queue, stream, database sink, etc.).
 *
 * <p>Keeping this as an interface lets the ingestion layer stay decoupled from the
 * eventual transport. Module 1 ships only the {@link DummyConsoleEventPublisher} stub;
 * later modules can supply a real queue-backed implementation.
 */
public interface EventPublisher {

    /**
     * Publishes a single validated event downstream.
     *
     * @param event the event to publish (already validated and stamped with {@code receivedAt})
     */
    void publish(SecurityEvent event);
}
