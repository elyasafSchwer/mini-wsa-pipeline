package com.es.wsa.storage;

import com.es.wsa.domain.GeoLocation;
import com.es.wsa.domain.Rule;
import com.es.wsa.domain.SecurityEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * {@link EventStorageService} backed by Elasticsearch via {@link SecurityEventRepository}.
 *
 * <p>Maps the immutable domain {@link SecurityEvent} onto a mutable
 * {@link SecurityEventDocument} (flattening the {@code Rule} and {@code GeoLocation}
 * sub-records and rendering enums as their names) and delegates the write to the
 * repository, which upserts by {@code eventId}.
 */
@Service
public class ElasticsearchStorageServiceImpl implements EventStorageService {

    private static final Logger log = LoggerFactory.getLogger(ElasticsearchStorageServiceImpl.class);

    private final SecurityEventRepository repository;

    public ElasticsearchStorageServiceImpl(SecurityEventRepository repository) {
        this.repository = repository;
    }

    @Override
    public String save(SecurityEvent event) {
        if (event == null) {
            throw new IllegalArgumentException("event must not be null");
        }

        SecurityEventDocument document = toDocument(event);
        SecurityEventDocument saved = repository.save(document);

        log.debug("Indexed event {} to Elasticsearch index 'security-events'", saved.getEventId());
        return saved.getEventId();
    }

    /**
     * Maps a domain event to its Elasticsearch document view, flattening nested records and
     * rendering enums as {@code name()} strings (stored as keywords).
     */
    private SecurityEventDocument toDocument(SecurityEvent event) {
        SecurityEventDocument doc = new SecurityEventDocument();

        doc.setEventId(event.eventId());
        doc.setTimestamp(event.timestamp());
        doc.setConfigId(event.configId());
        doc.setPolicyId(event.policyId());
        doc.setClientIp(event.clientIp());
        doc.setHostname(event.hostname());
        doc.setPath(event.path());
        doc.setMethod(event.method());
        doc.setStatusCode(event.statusCode());
        doc.setUserAgent(event.userAgent());
        doc.setRequestSize(event.requestSize());
        doc.setResponseSize(event.responseSize());
        doc.setReceivedAt(event.receivedAt());

        Rule rule = event.rule();
        if (rule != null) {
            doc.setRuleId(rule.id());
            doc.setRuleName(rule.name());
            doc.setRuleMessage(rule.message());
            doc.setRuleSeverity(rule.severity() == null ? null : rule.severity().name());
            doc.setRuleCategory(rule.category());
            doc.setRuleAction(rule.action() == null ? null : rule.action().name());
        }

        GeoLocation geo = event.geoLocation();
        if (geo != null) {
            doc.setGeoCountry(geo.country());
            doc.setGeoCity(geo.city());
        }

        doc.setAttackType(event.attackType());
        doc.setThreatScore(event.threatScore());
        doc.setRepeatOffender(event.repeatOffender());

        return doc;
    }
}
