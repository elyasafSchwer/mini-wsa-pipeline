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
}
