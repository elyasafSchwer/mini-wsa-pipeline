package com.es.wsa.messaging;

import com.es.wsa.domain.SecurityEvent;
import com.es.wsa.enrichment.EventProcessor;
import com.es.wsa.storage.EventStorageService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SecurityEventConsumer}. Runs the listener method directly
 * (synchronously) with a mocked {@link EventProcessor} and {@link EventStorageService} —
 * the {@code @Async} dispatch is Spring's concern, not this unit's.
 */
@ExtendWith(MockitoExtension.class)
class SecurityEventConsumerTest {

    @Mock
    private EventProcessor eventProcessor;

    @Mock
    private EventStorageService storageService;

    @Test
    void enrichesThenStoresEvent() {
        SecurityEventConsumer consumer = new SecurityEventConsumer(eventProcessor, storageService);
        SecurityEvent event = sampleEvent("evt-1");
        SecurityEvent enriched = event.withAttackType("SQLi").withThreatScore(80);
        when(eventProcessor.process(any())).thenReturn(enriched);

        consumer.onSecurityEvent(new SecurityEventMessage(event));

        verify(eventProcessor, times(1)).process(event);
        // The enriched event (not the raw one) is what gets persisted.
        verify(storageService, times(1)).save(enriched);
    }

    @Test
    void swallowsEnrichmentFailuresGracefully() {
        SecurityEventConsumer consumer = new SecurityEventConsumer(eventProcessor, storageService);
        SecurityEvent event = sampleEvent("evt-boom");
        when(eventProcessor.process(any())).thenThrow(new RuntimeException("enrichment blew up"));

        // The consumer must not propagate the failure — a poison event cannot crash the
        // consumer thread or block subsequent events.
        assertThatCode(() -> consumer.onSecurityEvent(new SecurityEventMessage(event)))
                .doesNotThrowAnyException();

        verify(eventProcessor).process(event);
        // Enrichment failed, so nothing should have been persisted.
        verify(storageService, never()).save(any());
    }

    @Test
    void swallowsStorageFailuresGracefully() {
        SecurityEventConsumer consumer = new SecurityEventConsumer(eventProcessor, storageService);
        SecurityEvent event = sampleEvent("evt-es-down");
        when(eventProcessor.process(any())).thenReturn(event);
        when(storageService.save(any())).thenThrow(new RuntimeException("elasticsearch down"));

        // A storage outage must be swallowed just like an enrichment failure.
        assertThatCode(() -> consumer.onSecurityEvent(new SecurityEventMessage(event)))
                .doesNotThrowAnyException();

        verify(storageService).save(event);
    }

    private static SecurityEvent sampleEvent(String id) {
        return new SecurityEvent(
                id, null, 1L, "p", "203.0.113.7", "h", "/x", "GET", 200,
                "ua", 1L, 1L, null, null, null, null, null);
    }
}
