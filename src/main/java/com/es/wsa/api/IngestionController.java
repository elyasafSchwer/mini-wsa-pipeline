package com.es.wsa.api;

import com.es.wsa.domain.SecurityEvent;
import com.es.wsa.publisher.EventPublisher;
import com.es.wsa.validation.SecurityEventValidator;
import com.es.wsa.validation.ValidationResult;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.NestedExceptionUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Ingestion endpoint for {@link SecurityEvent}s.
 *
 * <p>Accepts either a single event JSON object or a JSON array of events at
 * {@code POST /v1/events/ingest}. Every event is run through the
 * {@link SecurityEventValidator}; a request is accepted only if <em>all</em> of its
 * events are valid (all-or-nothing), at which point each event is stamped with the
 * server-side {@code receivedAt} timestamp and handed to the {@link EventPublisher}.
 *
 * <p>The controller is deliberately decoupled from the downstream Enrichment stage: it
 * depends only on the transport-agnostic {@link EventPublisher} interface and has no
 * knowledge of the underlying messaging (Spring events today, Kafka in the target
 * architecture). Enrichment happens asynchronously off the request thread, so ingestion
 * responds as soon as events are published.
 */
@RestController
@RequestMapping("/v1/events")
public class IngestionController {

    private static final Logger log = LoggerFactory.getLogger(IngestionController.class);

    private final SecurityEventValidator validator;
    private final EventPublisher publisher;
    private final ObjectMapper objectMapper;

    public IngestionController(SecurityEventValidator validator,
                               EventPublisher publisher,
                               ObjectMapper objectMapper) {
        this.validator = validator;
        this.publisher = publisher;
        this.objectMapper = objectMapper;
    }

    /**
     * Ingests one or many security events.
     *
     * @param body the raw JSON body — either a single event object or an array of them
     * @return {@code 201 Created} with an {@link IngestionResponse} when all events are
     * valid; {@code 400 Bad Request} with an {@link IngestionErrorResponse} otherwise
     */
    @PostMapping("/ingest")
    public ResponseEntity<?> ingest(@RequestBody JsonNode body) {
        List<SecurityEvent> events = parseEvents(body);
        if (events.isEmpty()) {
            return ResponseEntity.badRequest().body(new IngestionErrorResponse(
                    "Request body must be a security event object or a non-empty array of them",
                    List.of()));
        }

        // Validate everything first so we can report all problems and publish nothing on failure.
        List<IngestionErrorResponse.EventErrors> failures = new ArrayList<>();
        for (int i = 0; i < events.size(); i++) {
            ValidationResult result = validator.validate(events.get(i));
            if (!result.valid()) {
                failures.add(new IngestionErrorResponse.EventErrors(i, result.errors()));
            }
        }

        if (!failures.isEmpty()) {
            log.debug("Rejecting ingestion request: {} of {} events invalid", failures.size(), events.size());
            return ResponseEntity.badRequest().body(new IngestionErrorResponse(
                    "One or more events failed validation; no events were accepted", failures));
        }

        // All valid: stamp server receive time and hand off to the transport-agnostic
        // publisher. The controller depends only on the EventPublisher interface and is
        // unaware whether the underlying transport is Spring events (today) or Kafka
        // (future) — decoupling the Ingestion API from the Enrichment stage.
        OffsetDateTime receivedAt = OffsetDateTime.now();
        for (SecurityEvent event : events) {
            publisher.publish(event.withReceivedAt(receivedAt));
        }
        log.info("Accepted and published {} event(s) to internal queue", events.size());

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new IngestionResponse(events.size(), "Events accepted"));
    }

    /**
     * Converts the raw JSON body into a list of events, accepting both a single object
     * and an array. Returns an empty list for shapes that cannot carry events (e.g. a
     * scalar or an empty array), which the caller reports as a bad request.
     */
    private List<SecurityEvent> parseEvents(JsonNode body) {
        if (body == null || body.isNull()) {
            return List.of();
        }
        if (body.isArray()) {
            if (body.isEmpty()) {
                return List.of();
            }
            return objectMapper.convertValue(
                    body, objectMapper.getTypeFactory()
                            .constructCollectionType(List.class, SecurityEvent.class));
        }
        if (body.isObject()) {
            return List.of(objectMapper.convertValue(body, SecurityEvent.class));
        }
        return List.of();
    }

    /**
     * Translates malformed JSON (or a body Jackson cannot map onto a {@link SecurityEvent})
     * into a {@code 400} rather than a {@code 500}.
     */
    @ExceptionHandler({HttpMessageNotReadableException.class, IllegalArgumentException.class})
    public ResponseEntity<IngestionErrorResponse> handleUnreadable(Exception ex) {
        Throwable cause = NestedExceptionUtils.getMostSpecificCause(ex);
        return ResponseEntity.badRequest().body(new IngestionErrorResponse(
                "Malformed request body: " + cause.getMessage(), List.of()));
    }
}
