package com.es.wsa.standalone;

import com.es.wsa.domain.GeoLocation;
import com.es.wsa.domain.Rule;
import com.es.wsa.domain.SecurityEvent;
import com.es.wsa.storage.EventStorageService;
import com.es.wsa.storage.SecurityEventDocument;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

/**
 * In-memory {@link EventStorageService} for the {@code standalone} profile.
 *
 * <p>Marked {@link Primary} so it wins the {@code EventStorageService} injection over the
 * (still-present but unused) {@code ElasticsearchStorageServiceImpl} bean. The domain →
 * document mapping is a deliberate copy of {@code ElasticsearchStorageServiceImpl.toDocument}
 * so the in-memory documents are byte-identical to what Elasticsearch would store — keeping
 * the stats/samples read paths behaviourally identical across profiles.
 */
@Service
@Primary
@Profile("standalone")
public class InMemoryEventStorageService implements EventStorageService {

    private static final Logger log = LoggerFactory.getLogger(InMemoryEventStorageService.class);

    private final InMemoryEventStore store;

    public InMemoryEventStorageService(InMemoryEventStore store) {
        this.store = store;
    }

    @Override
    public String save(SecurityEvent event) {
        if (event == null) {
            throw new IllegalArgumentException("event must not be null");
        }

        SecurityEventDocument document = toDocument(event);
        SecurityEventDocument saved = store.save(document);

        log.debug("Stored event {} in the in-memory event store", saved.getEventId());
        return saved.getEventId();
    }

    /**
     * Maps a domain event to its document view, flattening nested records and rendering enums
     * as {@code name()} strings. Mirrors {@code ElasticsearchStorageServiceImpl.toDocument}.
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
