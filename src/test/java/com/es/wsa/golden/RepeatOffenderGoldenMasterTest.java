package com.es.wsa.golden;

import com.es.wsa.datagen.EventFileReader;
import com.es.wsa.domain.SecurityEvent;
import com.es.wsa.samples.SampleQuery;
import com.es.wsa.samples.SampleResponse;
import com.es.wsa.samples.SamplesService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;

import java.io.InputStream;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * Golden Master regression test that locks in the exact enriched output of the whole pipeline.
 *
 * <p>The run is end-to-end on the {@code standalone} profile (no Elasticsearch, no Redis, no
 * Docker): the canonical {@code events.csv} fixture (in {@code src/test/resources} so the test
 * owns its data) is ingested through the real HTTP ingestion API <strong>in its exact file
 * order</strong>, enrichment happens asynchronously on the
 * {@link com.es.wsa.messaging.KeyedExecutor} lanes, and the test then blocks on the
 * {@code /api/dev/processing-status} endpoint until every lane has drained — no
 * {@code Thread.sleep}, no arbitrary timing.
 *
 * <p><strong>Bit-by-bit verification against a static golden file.</strong> The expected final
 * state of all 10,000 events lives in {@code src/test/resources/expected-enriched-events.json}
 * — a captured, checked-in snapshot, <em>not</em> a re-derivation of the enrichment logic. Once
 * the pipeline is idle, every stored event is compared field-for-field against its golden
 * record. The only field excluded is {@code receivedAt} (server wall-clock stamp, not
 * deterministic; nulled in the golden file and asserted merely present here).
 *
 * <p>To regenerate the golden file after an <em>intended</em> behaviour change, run
 * {@code GoldenMasterFixtureGenerator} with {@code -DgenerateGolden=true} and review the diff.
 *
 * <p>Two extra hard-coded assertions guard the exact repeat-offender threshold boundary: the
 * total number of flagged events is exactly {@code 2400}, and client IP {@code 42.128.137.171}
 * (25 events, all inside one 10-minute window) shows the textbook {@code FFFFF} then {@code T…T}
 * sequence — {@code false} for its first five events, flipping to {@code true} on the sixth.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("standalone")
class RepeatOffenderGoldenMasterTest {

    /** Test-owned fixture on the classpath (src/test/resources/events.csv). */
    private static final String FIXTURE_RESOURCE = "/events.csv";
    /** Checked-in golden output (src/test/resources/expected-enriched-events.json). */
    private static final String GOLDEN_RESOURCE = "/expected-enriched-events.json";

    private static final int EXPECTED_EVENTS = 10_000;
    private static final int INGEST_BATCH = 500;

    /** A high-volume IP whose 25 events all fall in one window: expect FFFFF then 20×T. */
    private static final String BOUNDARY_IP = "42.128.137.171";
    /** Golden constant: flagged-event count across the whole fixture. */
    private static final long EXPECTED_TOTAL_FLAGGED = 2400L;

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate rest;

    @Autowired
    private SamplesService samplesService;

    @Autowired
    private ObjectMapper objectMapper;

    private List<SecurityEvent> fixture;

    @BeforeEach
    void loadFixture() {
        fixture = new EventFileReader().read(fixturePath());
        assertThat(fixture).as("fixture events").hasSize(EXPECTED_EVENTS);
    }

    @Test
    void enrichedStateMatchesGoldenMasterExactly() {
        ingestInOrder(fixture);
        waitUntilEnrichmentDrained(fixture.size());

        Map<String, SampleResponse.Sample> actual = storedSamplesByEventId();
        Map<String, SampleResponse.Sample> expected = goldenSamplesByEventId();

        // 1) COMPLETE, EXACT, PER-EVENT match against the checked-in golden file. Every field
        //    except the non-deterministic server-stamped receivedAt (asserted present below).
        assertThat(actual.keySet())
                .as("exactly the golden event ids are stored")
                .containsExactlyInAnyOrderElementsOf(expected.keySet());

        for (Map.Entry<String, SampleResponse.Sample> e : expected.entrySet()) {
            SampleResponse.Sample got = actual.get(e.getKey());
            assertThat(got)
                    .as("stored event %s must match the golden record on every field", e.getKey())
                    .usingRecursiveComparison()
                    .ignoringFields("receivedAt")
                    .isEqualTo(e.getValue());
            assertThat(got.receivedAt())
                    .as("event %s must be stamped with a server receivedAt", e.getKey())
                    .isNotNull();
        }

        // 2) Aggregate boundary: exact count of flagged events across the fixture.
        long flagged = actual.values().stream()
                .filter(SampleResponse.Sample::repeatOffender).count();
        assertThat(flagged).as("total repeat-offender flags").isEqualTo(EXPECTED_TOTAL_FLAGGED);

        // 3) Explicit FFFFF…T boundary for a single busy IP, in ingestion order.
        List<Boolean> boundarySeq = storedFlagsForIpInIngestOrder(actual, BOUNDARY_IP);
        assertThat(boundarySeq).as("boundary IP event count").hasSize(25);
        assertThat(boundarySeq.subList(0, 5))
                .as("first five events of %s are below threshold", BOUNDARY_IP)
                .containsExactly(false, false, false, false, false);
        assertThat(boundarySeq.subList(5, boundarySeq.size()))
                .as("sixth event onward exceeds threshold and stays flagged")
                .containsOnly(true);
    }

    // --- ingestion ----------------------------------------------------------------------

    /**
     * POSTs the events to {@code /v1/events/ingest} in file order, in sequential batches.
     * Batches are sent one after another and the controller publishes each array in order,
     * so per-IP submission order (and therefore per-IP enrichment order) matches the file.
     */
    private void ingestInOrder(List<SecurityEvent> events) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        for (int start = 0; start < events.size(); start += INGEST_BATCH) {
            List<SecurityEvent> batch = events.subList(start, Math.min(start + INGEST_BATCH, events.size()));
            String body = writeJson(batch);
            ResponseEntity<String> response = rest.postForEntity(
                    url("/v1/events/ingest"), new HttpEntity<>(body, headers), String.class);
            assertThat(response.getStatusCode())
                    .as("ingest batch starting at %d", start)
                    .isEqualTo(HttpStatus.CREATED);
        }
    }

    /**
     * Blocks until {@code /api/dev/processing-status} reports the enrichment lanes fully
     * drained — deterministically, via polling rather than sleeping. Requires the drained
     * state to be confirmed by the stored-event count as well, closing the tiny window where
     * a task has been dequeued but the store write has not yet landed.
     */
    private void waitUntilEnrichmentDrained(int expectedStored) {
        await("enrichment pipeline drains")
                .atMost(Duration.ofSeconds(60))
                .pollInterval(Duration.ofMillis(50))
                .until(() -> processingIdle() && storedCount() == expectedStored);
    }

    private boolean processingIdle() {
        ResponseEntity<ProcessingStatus> response = rest.getForEntity(
                url("/api/dev/processing-status"), ProcessingStatus.class);
        ProcessingStatus status = response.getBody();
        return status != null && status.idle();
    }

    // --- stored-state reads -------------------------------------------------------------

    private long storedCount() {
        return samplesService.findSamples(
                new SampleQuery(null, null, null, null, null, null, null, 1, 0)).total();
    }

    private Map<String, SampleResponse.Sample> storedSamplesByEventId() {
        Map<String, SampleResponse.Sample> byId = new HashMap<>();
        SampleResponse page = samplesService.findSamples(
                new SampleQuery(null, null, null, null, null, null, null, 20_000, 0));
        for (SampleResponse.Sample s : page.items()) {
            byId.put(s.eventId(), s);
        }
        assertThat(byId).as("one stored event per ingested event").hasSize(fixture.size());
        return byId;
    }

    /** Stored flags for one IP, ordered by the fixture's ingestion order. */
    private List<Boolean> storedFlagsForIpInIngestOrder(
            Map<String, SampleResponse.Sample> actual, String clientIp) {
        List<Boolean> ordered = new ArrayList<>();
        for (SecurityEvent e : fixture) {
            if (clientIp.equals(e.clientIp())) {
                ordered.add(actual.get(e.eventId()).repeatOffender());
            }
        }
        return ordered;
    }

    // --- golden file --------------------------------------------------------------------

    /** Loads the checked-in expected output, keyed by eventId. No enrichment logic here. */
    private Map<String, SampleResponse.Sample> goldenSamplesByEventId() {
        List<SampleResponse.Sample> golden;
        try (InputStream in = getClass().getResourceAsStream(GOLDEN_RESOURCE)) {
            assertThat(in).as("golden file %s present on classpath", GOLDEN_RESOURCE).isNotNull();
            golden = objectMapper.readValue(in, objectMapper.getTypeFactory()
                    .constructCollectionType(List.class, SampleResponse.Sample.class));
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to read golden file " + GOLDEN_RESOURCE, ex);
        }
        assertThat(golden).as("golden records").hasSize(EXPECTED_EVENTS);

        Map<String, SampleResponse.Sample> byId = new HashMap<>(golden.size() * 2);
        for (SampleResponse.Sample s : golden) {
            byId.put(s.eventId(), s);
        }
        return byId;
    }

    // --- helpers ------------------------------------------------------------------------

    private static Path fixturePath() {
        try {
            var url = RepeatOffenderGoldenMasterTest.class.getResource(FIXTURE_RESOURCE);
            if (url == null) {
                throw new IllegalStateException("Fixture not found on classpath: " + FIXTURE_RESOURCE);
            }
            return Path.of(url.toURI());
        } catch (Exception ex) {
            throw new IllegalStateException("Could not resolve fixture " + FIXTURE_RESOURCE, ex);
        }
    }

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    private String writeJson(List<SecurityEvent> events) {
        try {
            return objectMapper.writeValueAsString(events);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialise events for ingestion", e);
        }
    }

    /** Mirror of {@code DevDataGenController.ProcessingStatus} for JSON binding. */
    private record ProcessingStatus(boolean idle, int activeTasks, int queuedTasks) {
    }
}
