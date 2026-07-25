package com.es.wsa.ingest;

/**
 * Success body returned from {@code POST /v1/events/ingest}.
 *
 * @param accepted the number of events accepted and published
 * @param message  a short human-readable status message
 */
public record IngestionResponse(int accepted, String message) {
}
