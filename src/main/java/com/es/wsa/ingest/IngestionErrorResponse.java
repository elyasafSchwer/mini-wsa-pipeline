package com.es.wsa.ingest;

import java.util.List;

/**
 * Error body returned from {@code POST /v1/events/ingest} when one or more events fail
 * validation (or the payload itself is malformed). No events are published when this is
 * returned — ingestion is all-or-nothing per request.
 *
 * @param message a short summary of what went wrong
 * @param errors  per-event validation failures
 */
public record IngestionErrorResponse(String message, List<EventErrors> errors) {

    /**
     * Validation errors for a single event within the request payload.
     *
     * @param index    zero-based position of the event in the request
     *                 (0 for a single-object payload)
     * @param messages the validation error messages for that event
     */
    public record EventErrors(int index, List<String> messages) {
    }
}
