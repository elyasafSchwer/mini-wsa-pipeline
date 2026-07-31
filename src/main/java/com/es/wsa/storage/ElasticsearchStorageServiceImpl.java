package com.es.wsa.storage;

import com.es.wsa.domain.GeoLocation;
import com.es.wsa.domain.Rule;
import com.es.wsa.domain.SecurityEvent;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

/**
 * {@link EventStorageService} backed by Elasticsearch via {@link SecurityEventRepository},
 * writing in <strong>bulk batches</strong> rather than one document per event.
 *
 * <p>Maps the immutable domain {@link SecurityEvent} onto a mutable
 * {@link SecurityEventDocument} (flattening the {@code Rule} and {@code GeoLocation}
 * sub-records and rendering enums as their names), then buffers it. The buffer is drained
 * to Elasticsearch via {@link SecurityEventRepository#saveAll} (a single {@code _bulk}
 * request that upserts each document by {@code eventId}) when either:
 * <ul>
 *   <li>the buffer reaches {@code wsa.storage.batch-size} documents, or</li>
 *   <li>{@code wsa.storage.flush-interval-ms} elapses (a scheduled flush), so events
 *       never sit unindexed indefinitely under low traffic.</li>
 * </ul>
 * whichever comes first. A shutdown flush ({@link PreDestroy}) drains whatever remains.
 *
 * <p><strong>Consistency note:</strong> {@link #save(SecurityEvent)} now returns once the
 * event is <em>buffered</em>, not once it is durably indexed — the actual index write
 * happens on the size-triggered flush or the scheduled flush thread. This trades a small
 * visibility delay (bounded by the flush interval) for far fewer, larger ES round-trips.
 */
@Service
public class ElasticsearchStorageServiceImpl implements EventStorageService {

    private static final Logger log = LoggerFactory.getLogger(ElasticsearchStorageServiceImpl.class);

    private final SecurityEventRepository repository;

    /** Flush to Elasticsearch once the buffer reaches this many documents. */
    private final int batchSize;

    /** Buffer of pending documents plus the lock guarding it. */
    private final List<SecurityEventDocument> buffer = new ArrayList<>();
    private final ReentrantLock lock = new ReentrantLock();

    public ElasticsearchStorageServiceImpl(
            SecurityEventRepository repository,
            @Value("${wsa.storage.batch-size:500}") int batchSize) {
        this.repository = repository;
        this.batchSize = Math.max(1, batchSize);
        log.info("Elasticsearch bulk storage ready (batchSize={})", this.batchSize);
    }

    @Override
    public String save(SecurityEvent event) {
        if (event == null) {
            throw new IllegalArgumentException("event must not be null");
        }

        SecurityEventDocument document = toDocument(event);

        List<SecurityEventDocument> ready = null;
        lock.lock();
        try {
            buffer.add(document);
            if (buffer.size() >= batchSize) {
                ready = drainLocked();
            }
        } finally {
            lock.unlock();
        }

        // Perform the (blocking) bulk write outside the lock so other producers keep buffering.
        if (ready != null) {
            flushBatch(ready);
        }

        return document.getEventId();
    }

    /**
     * Scheduled time-based flush: pushes whatever is buffered to Elasticsearch on a fixed
     * interval so partial batches never linger when traffic is below {@code batchSize}. The
     * interval is {@code wsa.storage.flush-interval-ms} (default 1000ms).
     */
    @Scheduled(fixedRateString = "${wsa.storage.flush-interval-ms:1000}")
    public void flush() {
        List<SecurityEventDocument> ready;
        lock.lock();
        try {
            if (buffer.isEmpty()) {
                return;
            }
            ready = drainLocked();
        } finally {
            lock.unlock();
        }
        // No caller to propagate to on the scheduled/shutdown path — log and keep the loop alive.
        try {
            flushBatch(ready);
        } catch (Exception ex) {
            log.error("Scheduled bulk flush of {} event(s) failed: {}", ready.size(), ex.getMessage(), ex);
        }
    }

    /** Drains the shutdown remainder so buffered-but-unwritten events are not lost. */
    @PreDestroy
    public void flushOnShutdown() {
        log.info("Flushing remaining buffered events before shutdown");
        flush();
    }

    /** Copies out and clears the buffer. Caller must hold {@link #lock}. */
    private List<SecurityEventDocument> drainLocked() {
        List<SecurityEventDocument> batch = new ArrayList<>(buffer);
        buffer.clear();
        return batch;
    }

    /**
     * Writes one batch to Elasticsearch as a single bulk request. Failures are logged (and
     * rethrown to the caller for the size-triggered path) so a bad batch never silently
     * vanishes; the scheduled/shutdown paths swallow to keep the flush loop alive.
     */
    private void flushBatch(List<SecurityEventDocument> batch) {
        repository.saveAll(batch);
        log.debug("Bulk-indexed {} event(s) to Elasticsearch index 'security-events'", batch.size());
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
