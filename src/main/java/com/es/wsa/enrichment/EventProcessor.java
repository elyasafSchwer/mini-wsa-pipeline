package com.es.wsa.enrichment;

import com.es.wsa.domain.SecurityEvent;

/**
 * Processes a validated {@link SecurityEvent}, returning an enriched copy.
 *
 * <p>Enrichment augments the event with derived intelligence (attack type, threat score,
 * …) without mutating the original — implementations return a new {@link SecurityEvent}.
 * Kept as an interface so the enrichment strategy can evolve (or be composed) behind a
 * stable contract used by the ingestion pipeline.
 */
public interface EventProcessor {

    /**
     * Enriches a single event.
     *
     * @param event the validated event to enrich
     * @return an enriched copy of the event
     */
    SecurityEvent process(SecurityEvent event);
}
