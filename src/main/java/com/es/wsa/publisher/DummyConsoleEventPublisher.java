package com.es.wsa.publisher;

import com.es.wsa.domain.SecurityEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * A no-op {@link EventPublisher} that simply logs each event to standard output via
 * SLF4J. Used as a placeholder in Module 1 until a real queue-backed publisher is
 * introduced; contains no transport logic.
 */
@Component
public class DummyConsoleEventPublisher implements EventPublisher {

    private static final Logger log = LoggerFactory.getLogger(DummyConsoleEventPublisher.class);

    @Override
    public void publish(SecurityEvent event) {
        log.info("Publishing security event: {}", event);
    }
}
