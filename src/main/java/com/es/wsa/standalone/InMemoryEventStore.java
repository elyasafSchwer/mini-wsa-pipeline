package com.es.wsa.standalone;

import com.es.wsa.storage.SecurityEventDocument;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory replacement for the Elasticsearch {@code security-events} index, active only
 * under the {@code standalone} profile.
 *
 * <p>This is the single source of truth shared by every in-memory read/write bean:
 * {@link InMemoryEventStorageService} writes documents here; {@link InMemoryStatsService}
 * and {@link InMemorySamplesService} read them; and the in-memory {@code SecurityEventRepository}
 * proxy declared in {@link StandaloneConfig} exposes {@code count}/{@code deleteAll}/{@code save}
 * over the same map so {@code /api/dev/clear} reports a consistent count.
 *
 * <p>Keyed by {@code eventId} so writes are idempotent upserts — matching the Elasticsearch
 * behaviour of using the event id as the document id.
 */
@Component
@Profile("standalone")
public class InMemoryEventStore {

    private final Map<String, SecurityEventDocument> byId = new ConcurrentHashMap<>();

    /**
     * Upserts a document by its {@code eventId}.
     *
     * @param doc the document to store
     * @return the same document (mirrors {@code CrudRepository.save} returning the saved entity)
     */
    public SecurityEventDocument save(SecurityEventDocument doc) {
        byId.put(doc.getEventId(), doc);
        return doc;
    }

    /** @return the number of stored documents */
    public long count() {
        return byId.size();
    }

    /** Removes all stored documents. */
    public void clear() {
        byId.clear();
    }

    /** @return a snapshot copy of all stored documents */
    public List<SecurityEventDocument> all() {
        return new ArrayList<>(byId.values());
    }
}
