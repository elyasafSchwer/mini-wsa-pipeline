package com.es.wsa.dev;

import com.es.wsa.config.WsaPolicyProperties;
import com.es.wsa.datagen.AttackProfile;
import com.es.wsa.datagen.IngestionFeeder;
import com.es.wsa.datagen.SecurityEventGenerator;
import com.es.wsa.domain.SecurityEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

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
@RequestMapping("/v1/dev/datagen")
@Profile("dev")
public class DevDataGenController {

    private static final Logger log = LoggerFactory.getLogger(DevDataGenController.class);

    private final WsaPolicyProperties policies;
    private final int batchSize;
    private final String baseUrl;

    /**
     * @param policies   supplies the attack-category vocabulary the generator draws from
     * @param serverPort the running server's port, so the loopback base URL targets itself
     * @param baseUrl    optional explicit base-URL override ({@code wsa.datagen.ingest-base-url});
     *                   when unset, {@code http://localhost:<serverPort>} is used
     * @param batchSize  events per ingestion request ({@code wsa.datagen.batch-size}, default 50)
     */
    public DevDataGenController(
            WsaPolicyProperties policies,
            @Value("${local.server.port:8080}") int serverPort,
            @Value("${wsa.datagen.ingest-base-url:}") String baseUrl,
            @Value("${wsa.datagen.batch-size:50}") int batchSize) {
        this.policies = policies;
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
    @PostMapping("/run")
    public DevDataGenResult run(
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
     * Summary returned by the dev trigger.
     *
     * @param generated number of events generated
     * @param feed      the ingestion feed result
     */
    public record DevDataGenResult(int generated, IngestionFeeder.FeedResult feed) {
    }
}
