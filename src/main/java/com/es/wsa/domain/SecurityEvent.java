package com.es.wsa.domain;

import java.time.OffsetDateTime;

/**
 * A single web security event ingested by the WSA pipeline.
 *
 * <p>Modelled as an immutable record so it maps cleanly to/from JSON via Jackson and is
 * safe to hand off to downstream publishers without defensive copying. Fields fall into
 * three groups by origin:
 * <ul>
 *   <li>Client payload — everything from {@code eventId} through {@code geoLocation}.</li>
 *   <li>Server ingestion — {@code receivedAt}, stamped on arrival
 *       (see {@link #withReceivedAt(OffsetDateTime)}).</li>
 *   <li>Enrichment — {@code attackType} and {@code threatScore}, populated by the
 *       enrichment stage (see {@link #withAttackType(String)} /
 *       {@link #withThreatScore(Integer)}).</li>
 * </ul>
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
 * @param attackType   human-readable attack type derived from {@code rule.category}
 *                     during enrichment, may be {@code null} before enrichment
 * @param threatScore  computed risk score (0–100) assigned during enrichment,
 *                     may be {@code null} before enrichment
 * @param repeatOffender {@code true} when the repeat-offender bonus was applied to
 *                     {@code threatScore} during enrichment because the client IP exceeded
 *                     the rate-limit threshold; {@code false} before enrichment
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
        GeoLocation geoLocation,
        String attackType,
        Integer threatScore,
        boolean repeatOffender
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
                statusCode, userAgent, requestSize, responseSize, receivedAt, rule, geoLocation,
                attackType, threatScore, repeatOffender
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
                statusCode, userAgent, requestSize, responseSize, receivedAt, rule, geoLocation,
                attackType, threatScore, repeatOffender
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
                statusCode, userAgent, requestSize, responseSize, receivedAt, rule, geoLocation,
                attackType, threatScore, repeatOffender
        );
    }

    /**
     * Returns a copy of this event with the enrichment-derived {@code attackType} set.
     *
     * @param attackType the human-readable attack type
     * @return a new {@link SecurityEvent} with the given attack type
     */
    public SecurityEvent withAttackType(String attackType) {
        return new SecurityEvent(
                eventId, timestamp, configId, policyId, clientIp, hostname, path, method,
                statusCode, userAgent, requestSize, responseSize, receivedAt, rule, geoLocation,
                attackType, threatScore, repeatOffender
        );
    }

    /**
     * Returns a copy of this event with the enrichment-derived {@code threatScore} set.
     *
     * @param threatScore the computed risk score (0–100)
     * @return a new {@link SecurityEvent} with the given threat score
     */
    public SecurityEvent withThreatScore(Integer threatScore) {
        return new SecurityEvent(
                eventId, timestamp, configId, policyId, clientIp, hostname, path, method,
                statusCode, userAgent, requestSize, responseSize, receivedAt, rule, geoLocation,
                attackType, threatScore, repeatOffender
        );
    }

    /**
     * Returns a copy of this event with the enrichment-derived {@code repeatOffender} flag
     * set — {@code true} when the repeat-offender bonus was added to the threat score.
     *
     * @param repeatOffender whether the client IP was flagged as a repeat offender
     * @return a new {@link SecurityEvent} with the given repeat-offender flag
     */
    public SecurityEvent withRepeatOffender(boolean repeatOffender) {
        return new SecurityEvent(
                eventId, timestamp, configId, policyId, clientIp, hostname, path, method,
                statusCode, userAgent, requestSize, responseSize, receivedAt, rule, geoLocation,
                attackType, threatScore, repeatOffender
        );
    }
}
