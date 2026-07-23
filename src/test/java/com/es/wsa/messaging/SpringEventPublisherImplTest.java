package com.es.wsa.messaging;

import com.es.wsa.domain.SecurityEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;

/**
 * Unit tests for {@link SpringEventPublisherImpl}: it must wrap the event in a
 * {@link SecurityEventMessage} envelope and hand it to Spring's
 * {@link ApplicationEventPublisher}, without the caller knowing the transport.
 */
@ExtendWith(MockitoExtension.class)
class SpringEventPublisherImplTest {

    @Mock
    private ApplicationEventPublisher applicationEventPublisher;

    @Test
    void publishesEventWrappedInEnvelope() {
        SpringEventPublisherImpl publisher = new SpringEventPublisherImpl(applicationEventPublisher);
        SecurityEvent event = sampleEvent("evt-42", "203.0.113.7");

        publisher.publish(event);

        ArgumentCaptor<SecurityEventMessage> captor = ArgumentCaptor.forClass(SecurityEventMessage.class);
        verify(applicationEventPublisher).publishEvent(captor.capture());
        assertThat(captor.getValue().event()).isSameAs(event);
        assertThat(captor.getValue().partitionKey()).isEqualTo("203.0.113.7");
    }

    private static SecurityEvent sampleEvent(String id, String clientIp) {
        return new SecurityEvent(
                id, null, 1L, "p", clientIp, "h", "/x", "GET", 200,
                "ua", 1L, 1L, null, null, null, null, null, false);
    }
}
