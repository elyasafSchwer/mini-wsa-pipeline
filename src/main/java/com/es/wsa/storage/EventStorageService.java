package com.es.wsa.storage;

import com.es.wsa.domain.SecurityEvent;

/**
 * Persists enriched {@link SecurityEvent}s to long-term storage for analytics.
 *
 * <p>Kept as an interface (mirroring {@code EventProcessor}) so the storage backend —
 * Elasticsearch today (see {@link ElasticsearchStorageServiceImpl}) — can be swapped or
 * fronted by a buffering/bulk layer without touching the pipeline that calls it.
 */
public interface EventStorageService {

    /**
     * Persists a single fully-enriched event.
     *
     * @param event the enriched event to store; must not be {@code null}
     * @return the id under which the event was stored (the event id)
     */
    String save(SecurityEvent event);
}
