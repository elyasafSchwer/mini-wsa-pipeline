package com.es.wsa.samples;

/**
 * Retrieves individual enriched event records matching a filter, with pagination.
 *
 * <p>Kept as an interface (mirroring {@code StatsService}) so the retrieval backend —
 * Elasticsearch today (see {@link ElasticsearchSamplesService}) — can be swapped without
 * touching the controller.
 */
public interface SamplesService {

    /**
     * Returns a page of events matching the (already validated) query, sorted by event
     * {@code timestamp} descending.
     *
     * @param query the filter + pagination parameters
     * @return the matching records plus the total match count
     */
    SampleResponse findSamples(SampleQuery query);
}
