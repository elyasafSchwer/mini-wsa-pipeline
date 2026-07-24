package com.es.wsa.samples;

import java.util.List;

/**
 * A page of individual enriched event records matching a samples query, returned by
 * {@code GET /v1/events/samples}.
 *
 * <p>{@code total} is the full count of matching events (independent of paging), so a
 * client can compute the number of pages. {@code items} holds at most {@code limit}
 * records for the requested {@code offset}, sorted by event {@code timestamp} descending
 * (newest first).
 *
 * @param total  total number of events matching the filters (ignoring paging)
 * @param limit  the effective page size used
 * @param offset the effective offset used
 * @param items  the matching event records for this page
 */
public record SampleResponse(
        long total,
        int limit,
        int offset,
        List<Sample> items
) {

    /**
     * A single enriched event record, flattened for the read API (nested rule/geo fields
     * are surfaced as {@code rule*}/{@code geo*} scalars, matching the storage document).
     */
    public record Sample(
            String eventId,
            String timestamp,
            Long configId,
            String policyId,
            String clientIp,
            String hostname,
            String path,
            String method,
            Integer statusCode,
            String ruleCategory,
            String ruleSeverity,
            String ruleAction,
            String attackType,
            Integer threatScore,
            boolean repeatOffender,
            String geoCountry,
            String receivedAt
    ) {
    }
}
