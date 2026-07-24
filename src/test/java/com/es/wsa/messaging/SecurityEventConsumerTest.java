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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SecurityEventConsumer}.
 *
 * <p>The enrich→store body is exercised via the synchronous {@link SecurityEventConsumer#process}
 * method (lane dispatch is {@link KeyedExecutor}'s concern, covered separately). A dedicated
 * test verifies {@code onSecurityEvent} routes to the keyed executor by the message's
 * partition key.
 */
@ExtendWith(MockitoExtension.class)
class SecurityEventConsumerTest {

    @Mock
    private EventProcessor eventProcessor;

    @Mock
    private EventStorageService storageService;

    @Mock
    private KeyedExecutor enrichmentExecutor;

    private SecurityEventConsumer consumer() {
        return new SecurityEventConsumer(eventProcessor, storageService, enrichmentExecutor);
    }

    @Test
    void enrichesThenStoresEvent() {
        SecurityEvent event = sampleEvent("evt-1");
        SecurityEvent enriched = event.withAttackType("SQLi").withThreatScore(80);
        when(eventProcessor.process(any())).thenReturn(enriched);

        consumer().process(new SecurityEventMessage(event));

        verify(eventProcessor, times(1)).process(event);
        // The enriched event (not the raw one) is what gets persisted.
        verify(storageService, times(1)).save(enriched);
    }

    @Test
    void swallowsEnrichmentFailuresGracefully() {
        SecurityEvent event = sampleEvent("evt-boom");
        when(eventProcessor.process(any())).thenThrow(new RuntimeException("enrichment blew up"));

        // A poison event cannot crash the lane or block subsequent events.
        assertThatCode(() -> consumer().process(new SecurityEventMessage(event)))
                .doesNotThrowAnyException();

        verify(eventProcessor).process(event);
        verify(storageService, never()).save(any());
    }

    @Test
    void swallowsStorageFailuresGracefully() {
        SecurityEvent event = sampleEvent("evt-es-down");
        when(eventProcessor.process(any())).thenReturn(event);
        when(storageService.save(any())).thenThrow(new RuntimeException("elasticsearch down"));

        assertThatCode(() -> consumer().process(new SecurityEventMessage(event)))
                .doesNotThrowAnyException();

        verify(storageService).save(event);
    }

    @Test
    void routesByPartitionKeyThenRunsProcessing() {
        SecurityEvent event = sampleEvent("evt-route");   // clientIp 203.0.113.7
        SecurityEventMessage message = new SecurityEventMessage(event);
        when(eventProcessor.process(any())).thenReturn(event);

        // Make the mock executor run the submitted task inline so we can assert its effect.
        doAnswer(inv -> {
            Runnable task = inv.getArgument(1);
            task.run();
            return null;
        }).when(enrichmentExecutor).execute(eq("203.0.113.7"), any());

        consumer().onSecurityEvent(message);

        // Routed with the client IP as the key, and processing ran (enrich + store).
        verify(enrichmentExecutor).execute(eq("203.0.113.7"), any());
        verify(eventProcessor).process(event);
        verify(storageService).save(event);
    }

    private static SecurityEvent sampleEvent(String id) {
        return new SecurityEvent(
                id, null, 1L, "p", "203.0.113.7", "h", "/x", "GET", 200,
                "ua", 1L, 1L, null, null, null, null, null, false);
    }
}
