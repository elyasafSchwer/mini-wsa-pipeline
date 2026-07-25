package com.es.wsa.dev;

import com.es.wsa.config.WsaPolicyProperties;
import com.es.wsa.datagen.AttackProfile;
import com.es.wsa.datagen.EventFileReader;
import com.es.wsa.datagen.IngestionFeeder;
import com.es.wsa.datagen.SecurityEventGenerator;
import com.es.wsa.domain.SecurityEvent;
import com.es.wsa.messaging.KeyedExecutor;
import com.es.wsa.ratelimit.IpRateTrackerService;
import com.es.wsa.storage.SecurityEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/**
 * Secret, developer-only trigger that runs the whole data-generation flow internally:
 * generate a batch of events in memory and feed them straight to the ingestion API
 * (server-to-server over the loopback HTTP client).
 *
 * <p>This is the <em>only</em> Spring-managed piece of the data-generation tooling. The
 * generator ({@link SecurityEventGenerator}) and feeder ({@link IngestionFeeder}) are plain
 * classes (in {@code com.es.wsa.datagen}) that this controller constructs and calls
 * directly; nothing else wires them.
 *
 * <p>The controller bean only exists under the {@code dev} profile, so the route is simply
 * absent — a {@code 404} — in any environment where {@code dev} is not active. It is
 * intentionally undocumented and kept off the public API surface.
 *
 * <p>Because it drives the real {@link IngestionFeeder} (HTTP POST to
 * {@code /v1/events/ingest}), a single call exercises generation, batching, JSON
 * (de)serialization, validation, enrichment and storage end to end.
 */
@RestController
@RequestMapping("/api/dev")
@Profile("dev")
public class DevDataGenController {

    private static final Logger log = LoggerFactory.getLogger(DevDataGenController.class);

    private final WsaPolicyProperties policies;
    private final SecurityEventRepository repository;
    private final StringRedisTemplate redis;
    private final KeyedExecutor enrichmentExecutor;
    private final int batchSize;
    private final String baseUrl;

    /**
     * @param policies   supplies the attack-category vocabulary the generator draws from
     * @param repository used by {@code /clear} to delete all indexed events
     * @param redis      used by {@code /clear} to delete all per-IP rate-tracker keys
     * @param enrichmentExecutor the enrichment lanes, interrogated by {@code /processing-status}
     * @param serverPort the running server's port, so the loopback base URL targets itself
     * @param baseUrl    optional explicit base-URL override ({@code wsa.datagen.ingest-base-url});
     *                   when unset, {@code http://localhost:<serverPort>} is used
     * @param batchSize  events per ingestion request ({@code wsa.datagen.batch-size}, default 50)
     */
    public DevDataGenController(
            WsaPolicyProperties policies,
            SecurityEventRepository repository,
            StringRedisTemplate redis,
            KeyedExecutor enrichmentExecutor,
            @Value("${local.server.port:8080}") int serverPort,
            @Value("${wsa.datagen.ingest-base-url:}") String baseUrl,
            @Value("${wsa.datagen.batch-size:50}") int batchSize) {
        this.policies = policies;
        this.repository = repository;
        this.redis = redis;
        this.enrichmentExecutor = enrichmentExecutor;
        this.batchSize = batchSize;
        this.baseUrl = (baseUrl == null || baseUrl.isBlank())
                ? "http://localhost:" + serverPort
                : baseUrl;
    }

    /**
     * Generates and ingests a dataset in one server-to-server round trip.
     *
     * @param count     total events to generate; defaults to the profile default
     * @param seed      RNG seed for a reproducible dataset; optional
     * @param waveRatio fraction of events belonging to attack waves in {@code [0, 1]}; optional
     * @return a summary of what was generated and the feed result
     */
    @PostMapping("/generate")
    public DevDataGenResult generate(
            @RequestParam(required = false) Integer count,
            @RequestParam(required = false) Long seed,
            @RequestParam(required = false) Double waveRatio) {

        AttackProfile profile = buildProfile(count, seed, waveRatio);

        SecurityEventGenerator generator = new SecurityEventGenerator(policies.categoryKeys());
        List<SecurityEvent> events = generator.generate(profile);

        IngestionFeeder feeder = new IngestionFeeder(baseUrl, batchSize);
        IngestionFeeder.FeedResult feedResult = feeder.feed(events);

        log.info("[dev] datagen run against {}: generated {}, {}", baseUrl, events.size(), feedResult);
        return new DevDataGenResult(events.size(), feedResult);
    }

    /**
     * Deletes every document from the {@code security-events} index and every per-IP
     * rate-tracker key from Redis (keys matching {@code ip_events:*}).
     *
     * @return the number of Elasticsearch documents and Redis keys that were deleted
     */
    @PostMapping("/clear")
    public ClearResult clear() {
        long deletedEvents = repository.count();
        repository.deleteAll();

        Set<String> rateKeys = redis.keys(IpRateTrackerService.KEY_PREFIX + "*");
        long deletedRateKeys = 0;
        if (rateKeys != null && !rateKeys.isEmpty()) {
            deletedRateKeys = redis.delete(rateKeys);
        }

        log.info("[dev] cleared {} event(s) from ES and {} rate-tracker key(s) from Redis",
                deletedEvents, deletedRateKeys);
        return new ClearResult(deletedEvents, deletedRateKeys);
    }

    /**
     * Reports whether the asynchronous enrichment pipeline has fully drained: no task is
     * executing and none is queued on any {@link KeyedExecutor} lane.
     *
     * <p>Exists so tests and tooling can deterministically wait for all ingested events to
     * finish enrichment before asserting on the final state — polling this instead of
     * sleeping an arbitrary duration. Because ingestion publishes onto the lanes synchronously,
     * a caller that has finished submitting and then observes {@code idle == true} (ideally
     * stable across two consecutive reads) knows every event has been processed and stored.
     *
     * @return the current active/queued task counts and the derived idle flag
     */
    @GetMapping("/processing-status")
    public ProcessingStatus processingStatus() {
        int active = enrichmentExecutor.activeTaskCount();
        int queued = enrichmentExecutor.queuedTaskCount();
        return new ProcessingStatus(active == 0 && queued == 0, active, queued);
    }

    /**
     * Accepts a JSON or CSV file upload and feeds its events through the ingestion API
     * (server-to-server over the loopback HTTP client), exactly like {@link #generate}.
     * The format is auto-detected from the original filename extension ({@code .json} or
     * {@code .csv}).
     *
     * @param file the uploaded event file
     * @return a summary of events read and the feed result
     */
    @PostMapping(value = "/upload", consumes = "multipart/form-data")
    public DevDataGenResult upload(@RequestParam("file") MultipartFile file) {
        String originalName = file.getOriginalFilename() == null ? "upload" : file.getOriginalFilename();
        Path tmp;
        try {
            String suffix = originalName.contains(".")
                    ? originalName.substring(originalName.lastIndexOf('.'))
                    : "";
            tmp = Files.createTempFile("wsa-upload-", suffix);
            file.transferTo(tmp);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to store uploaded file", e);
        }

        try {
            List<SecurityEvent> events = new EventFileReader().read(tmp);
            IngestionFeeder feeder = new IngestionFeeder(baseUrl, batchSize);
            IngestionFeeder.FeedResult feedResult = feeder.feed(events);
            log.info("[dev] upload '{}' against {}: read {}, {}", originalName, baseUrl, events.size(), feedResult);
            return new DevDataGenResult(events.size(), feedResult);
        } finally {
            try {
                Files.deleteIfExists(tmp);
            } catch (IOException ignored) {
            }
        }
    }

    /** Overlays the supplied parameters onto {@link AttackProfile#withDefaults()}. */
    private AttackProfile buildProfile(Integer count, Long seed, Double waveRatio) {
        AttackProfile defaults = AttackProfile.withDefaults();
        return new AttackProfile(
                count == null ? defaults.totalEvents() : count,
                waveRatio == null ? defaults.attackWaveRatio() : waveRatio,
                defaults.waveSize(),
                defaults.waveWindow(),
                defaults.configIds(),
                defaults.timeSpan(),
                seed);
    }

    /**
     * Summary returned by the dev generate/upload triggers.
     *
     * @param generated number of events read/generated
     * @param feed      the ingestion feed result
     */
    public record DevDataGenResult(int generated, IngestionFeeder.FeedResult feed) {
    }

    /**
     * Summary returned by the dev clear trigger.
     *
     * @param deletedEvents    number of Elasticsearch documents deleted
     * @param deletedRateKeys  number of Redis rate-tracker keys deleted
     */
    public record ClearResult(long deletedEvents, long deletedRateKeys) {
    }

    /**
     * Snapshot of the enrichment pipeline's drain state, returned by
     * {@code GET /api/dev/processing-status}.
     *
     * @param idle        {@code true} when no enrichment task is executing or queued
     * @param activeTasks number of enrichment tasks currently running across all lanes
     * @param queuedTasks number of enrichment tasks waiting in lane queues
     */
    public record ProcessingStatus(boolean idle, int activeTasks, int queuedTasks) {
    }
}
