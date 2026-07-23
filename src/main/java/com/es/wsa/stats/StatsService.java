package com.es.wsa.stats;

/**
 * Computes aggregated {@link StatsSummaryResponse}s over the stored security events.
 *
 * <p>Kept as an interface so the aggregation backend — Elasticsearch today
 * (see {@link ElasticsearchStatsService}) — can be swapped or fronted by a cache without
 * touching the controller.
 */
public interface StatsService {

    /**
     * Aggregates statistics for the given (already validated) query.
     *
     * @param query the configuration/time-range filter; any field may be {@code null} to
     *              leave that dimension unconstrained
     * @return the aggregated summary
     */
    StatsSummaryResponse summarize(StatsQuery query);

    /**
     * Buckets event counts by a fixed time interval over the query's range, for charting.
     *
     * <p>The caller is expected to have validated that {@code query.from()} and
     * {@code query.to()} are both present (they bound the histogram axis and the zero-fill
     * extended bounds).
     *
     * @param query    the configuration/time-range filter; {@code from} and {@code to} must
     *                 be set
     * @param interval the bucket granularity
     * @return contiguous per-interval counts (zero-count intervals included)
     */
    TimeSeriesResponse timeseries(StatsQuery query, TimeInterval interval);
}
