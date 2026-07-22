package com.es.wsa.domain;

import java.time.OffsetDateTime;

/**
 * A single web security event ingested by the WSA pipeline.
 *
 * <p>Modelled as an immutable record so it maps cleanly to/from JSON via Jackson and is
 * safe to hand off to downstream publishers without defensive copying. All fields except
 * {@code receivedAt} originate from the client payload; {@code receivedAt} is stamped by
 * the server on ingestion (see {@link #withReceivedAt(OffsetDateTime)}).
 *
 * @param eventId      client-supplied unique event identifier
 * @param timestamp    time the event occurred at the edge
 * @param configId     security configuration identifier
 * @param policyId     security policy identifier
 * @param clientIp     originating client IP address
 * @param hostname     requested host
 * @param path         requested path
 * @param method       HTTP method
 * @param statusCode   HTTP response status code
 * @param userAgent    client user-agent string, may be {@code null}
 * @param requestSize  request size in bytes, may be {@code null}
 * @param responseSize response size in bytes, may be {@code null}
 * @param receivedAt   server-side ingestion timestamp (set by the server, not the client)
 * @param rule         the security rule that matched
 * @param geoLocation  geographic origin of the client, may be {@code null}
 */
public record SecurityEvent(
        String eventId,
        OffsetDateTime timestamp,
        Long configId,
        String policyId,
        String clientIp,
        String hostname,
        String path,
        String method,
        Integer statusCode,
        String userAgent,
        Long requestSize,
        Long responseSize,
        OffsetDateTime receivedAt,
        Rule rule,
        GeoLocation geoLocation
) {

    /**
     * Returns a copy of this event with {@code receivedAt} set to the given time.
     * Used by the ingestion layer to stamp the server-side arrival timestamp without
     * mutating the immutable payload.
     *
     * @param receivedAt the server-side ingestion time to stamp
     * @return a new {@link SecurityEvent} identical to this one but with {@code receivedAt} set
     */
    public SecurityEvent withReceivedAt(OffsetDateTime receivedAt) {
        return new SecurityEvent(
                eventId, timestamp, configId, policyId, clientIp, hostname, path, method,
                statusCode, userAgent, requestSize, responseSize, receivedAt, rule, geoLocation
        );
    }

    /**
     * Returns a copy of this event with a different {@code eventId}.
     *
     * @param eventId the new event id (may be {@code null})
     * @return a new {@link SecurityEvent} with the given event id
     */
    public SecurityEvent withEventId(String eventId) {
        return new SecurityEvent(
                eventId, timestamp, configId, policyId, clientIp, hostname, path, method,
                statusCode, userAgent, requestSize, responseSize, receivedAt, rule, geoLocation
        );
    }

    /**
     * Returns a copy of this event with a different {@link Rule}.
     *
     * @param rule the new rule (may be {@code null})
     * @return a new {@link SecurityEvent} with the given rule
     */
    public SecurityEvent withRule(Rule rule) {
        return new SecurityEvent(
                eventId, timestamp, configId, policyId, clientIp, hostname, path, method,
                statusCode, userAgent, requestSize, responseSize, receivedAt, rule, geoLocation
        );
    }
}
