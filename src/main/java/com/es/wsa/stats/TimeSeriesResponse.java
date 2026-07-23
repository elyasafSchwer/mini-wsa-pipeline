package com.es.wsa.stats;

import java.util.List;

/**
 * Event counts bucketed by a fixed time interval, returned by
 * {@code GET /v1/stats/timeseries} and suitable for drawing a line chart.
 *
 * <p>The bucket list is contiguous across the requested {@code [from, to]} range: intervals
 * with no events are still present with a {@code count} of {@code 0} (the underlying
 * aggregation uses {@code min_doc_count = 0} plus {@code extended_bounds}), so a chart can
 * plot an unbroken line without interpolating gaps.
 *
 * @param configId  the configuration these counts are scoped to, or {@code null} when
 *                  aggregated across all configurations
 * @param timeRange the echoed request time range (ISO-8601 strings)
 * @param interval  the echoed bucket-interval token (e.g. {@code "5m"})
 * @param buckets   per-interval counts, ordered from oldest to newest
 */
public record TimeSeriesResponse(
        Long configId,
        TimeRange timeRange,
        String interval,
        List<Bucket> buckets
) {

    /**
     * The request time range, echoed back as the original ISO-8601 strings.
     *
     * @param from inclusive lower bound (ISO-8601), or {@code null}
     * @param to   inclusive upper bound (ISO-8601), or {@code null}
     */
    public record TimeRange(String from, String to) {
    }

    /**
     * One interval's event count.
     *
     * @param timestamp ISO-8601 start of the bucket
     * @param count     number of events whose {@code timestamp} falls in this interval
     */
    public record Bucket(String timestamp, long count) {
    }
}
