package com.es.wsa.storage;

import org.springframework.data.elasticsearch.repository.ElasticsearchRepository;
import org.springframework.stereotype.Repository;

/**
 * Spring Data Elasticsearch repository for {@link SecurityEventDocument}s in the
 * {@code security-events} index, keyed by the event id ({@link String}).
 *
 * <p>Inherits the standard CRUD surface ({@code save}, {@code findById}, {@code count},
 * …). Derived query methods (e.g. {@code findByClientIp}, {@code findByThreatScoreGreaterThan})
 * can be added here later without an implementation, per the Spring Data convention.
 */
@Repository
public interface SecurityEventRepository
        extends ElasticsearchRepository<SecurityEventDocument, String> {
}
