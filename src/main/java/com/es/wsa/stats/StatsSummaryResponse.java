package com.es.wsa.stats;

import java.util.List;
import java.util.Map;

/**
 * Aggregated statistics for a configuration and time range, returned by
 * {@code GET /v1/stats/summary}.
 *
 * <p>All figures are computed server-side by Elasticsearch aggregations; the app never
 * loads the underlying documents. Breakdown maps use insertion order (Elasticsearch
 * returns terms buckets already ordered by descending count), so the JSON reflects the
 * most significant buckets first.
 *
 * @param configId        the configuration these stats are scoped to, or {@code null} when
 *                        aggregated across all configurations
 * @param timeRange       the echoed request time range (either bound may be {@code null})
 * @param totalEvents     total number of events matching the filter
 * @param byCategory      per attack-category breakdown (count + average threat score);
 *                        events with no category fall into the {@code "UNKNOWN"} bucket
 * @param byAction        per enforcement-action event counts; events with no action fall
 *                        into the {@code "UNKNOWN"} bucket
 * @param topAttackers    up to 10 client IPs by event count, most active first
 * @param topTargetedPaths up to 10 request paths by event count, most targeted first
 * @param avgThreatScore  mean threat score across all matching events (one decimal place)
 */
public record StatsSummaryResponse(
        Long configId,
        TimeRange timeRange,
        long totalEvents,
        Map<String, CategoryStat> byCategory,
        Map<String, Long> byAction,
        List<AttackerStat> topAttackers,
        List<PathStat> topTargetedPaths,
        double avgThreatScore
) {

    /**
     * The request time range, echoed back as the original ISO-8601 strings.
     *
     * @param from inclusive lower bound, or {@code null} if unbounded
     * @param to   inclusive upper bound, or {@code null} if unbounded
     */
    public record TimeRange(String from, String to) {
    }

    /**
     * Statistics for a single attack category.
     *
     * @param count          number of events in this category
     * @param avgThreatScore mean threat score for this category (one decimal place)
     */
    public record CategoryStat(long count, double avgThreatScore) {
    }

    /**
     * A high-volume client IP.
     *
     * @param clientIp       the client IP address (or {@code "UNKNOWN"} when absent)
     * @param count          number of events from this IP
     * @param avgThreatScore mean threat score for this IP's events (one decimal place)
     */
    public record AttackerStat(String clientIp, long count, double avgThreatScore) {
    }

    /**
     * A frequently targeted request path.
     *
     * @param path  the request path (or {@code "UNKNOWN"} when absent)
     * @param count number of events against this path
     */
    public record PathStat(String path, long count) {
    }
}
