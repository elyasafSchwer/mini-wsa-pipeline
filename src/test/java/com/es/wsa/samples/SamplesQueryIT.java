package com.es.wsa.samples;

import com.es.wsa.domain.Action;
import com.es.wsa.domain.GeoLocation;
import com.es.wsa.domain.Rule;
import com.es.wsa.domain.SecurityEvent;
import com.es.wsa.domain.Severity;
import com.es.wsa.storage.ElasticsearchStorageServiceImpl;
import com.es.wsa.storage.SecurityEventDocument;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.elasticsearch.client.elc.NativeQuery;
import org.springframework.data.elasticsearch.core.ElasticsearchOperations;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.time.OffsetDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration test for {@link ElasticsearchSamplesService} against the local docker-compose
 * Elasticsearch. Self-skipping when ES is unreachable (mirrors {@code StatsAggregationIT}).
 * Fixtures are tagged with a per-run unique {@code configId} for isolation and deleted in
 * teardown.
 */
@SpringBootTest
class SamplesQueryIT {

    private static final long CONFIG = 910_000_000L + (System.nanoTime() % 1_000_000L);

    @Autowired
    private ElasticsearchStorageServiceImpl storageService;

    @Autowired
    private SamplesService samplesService;

    @Autowired
    private ElasticsearchOperations operations;

    @BeforeEach
    void requireElasticsearch() {
        assumeTrue(elasticsearchReachable(),
                "Elasticsearch not reachable on localhost:9200 — skipping samples IT.");
        indexFixtures();
    }

    @AfterEach
    void cleanup() {
        if (!elasticsearchReachable()) {
            return;
        }
        NativeQuery mine = NativeQuery.builder()
                .withQuery(q -> q.term(t -> t.field("configId").value(CONFIG)))
                .build();
        operations.delete(mine, SecurityEventDocument.class);
        operations.indexOps(SecurityEventDocument.class).refresh();
    }

    @Test
    void returnsMatchingEventsNewestFirstWithTotal() {
        // configId filter -> all 5 fixtures; sorted by timestamp desc.
        SampleResponse page = samplesService.findSamples(
                new SampleQuery(CONFIG, null, null, null, null, null, null, 20, 0));

        assertThat(page.total()).isEqualTo(5);
        assertThat(page.items()).hasSize(5);
        // Newest first: 10:04 ... 10:00.
        assertThat(page.items())
                .extracting(SampleResponse.Sample::eventId)
                .containsExactly(
                        CONFIG + "-e5", CONFIG + "-e4", CONFIG + "-e3", CONFIG + "-e2", CONFIG + "-e1");
    }

    @Test
    void filtersByCategoryAndAction() {
        // e1,e2,e3 are INJECTION; of those e1,e3 are DENY.
        SampleResponse page = samplesService.findSamples(
                new SampleQuery(CONFIG, null, null, null, "INJECTION", "DENY", null, 20, 0));

        assertThat(page.total()).isEqualTo(2);
        assertThat(page.items()).extracting(SampleResponse.Sample::ruleCategory)
                .containsOnly("INJECTION");
        assertThat(page.items()).extracting(SampleResponse.Sample::ruleAction)
                .containsOnly("DENY");
    }

    @Test
    void filtersByClientIp() {
        // Only e4 was sent from 198.51.100.9; the rest from 203.0.113.7.
        SampleResponse page = samplesService.findSamples(
                new SampleQuery(CONFIG, "198.51.100.9", null, null, null, null, null, 20, 0));

        assertThat(page.total()).isEqualTo(1);
        assertThat(page.items()).singleElement()
                .extracting(SampleResponse.Sample::eventId).isEqualTo(CONFIG + "-e4");
        assertThat(page.items().get(0).clientIp()).isEqualTo("198.51.100.9");
    }

    @Test
    void filtersByRepeatOffender() {
        // Only e3 and e1 are flagged repeat offenders; newest-first -> e3 then e1.
        SampleResponse page = samplesService.findSamples(
                new SampleQuery(CONFIG, null, null, null, null, null, true, 20, 0));

        assertThat(page.total()).isEqualTo(2);
        assertThat(page.items()).extracting(SampleResponse.Sample::repeatOffender).containsOnly(true);
        assertThat(page.items())
                .extracting(SampleResponse.Sample::eventId)
                .containsExactly(CONFIG + "-e3", CONFIG + "-e1");

        // The complementary filter returns the other three.
        SampleResponse notOffenders = samplesService.findSamples(
                new SampleQuery(CONFIG, null, null, null, null, null, false, 20, 0));
        assertThat(notOffenders.total()).isEqualTo(3);
        assertThat(notOffenders.items()).extracting(SampleResponse.Sample::repeatOffender)
                .containsOnly(false);
    }

    @Test
    void paginatesWithLimitAndOffset() {
        // total stays 5 regardless of paging; page 2 (offset 2, limit 2) returns e3,e2.
        SampleResponse page = samplesService.findSamples(
                new SampleQuery(CONFIG, null, null, null, null, null, null, 2, 2));

        assertThat(page.total()).isEqualTo(5);
        assertThat(page.limit()).isEqualTo(2);
        assertThat(page.offset()).isEqualTo(2);
        assertThat(page.items())
                .extracting(SampleResponse.Sample::eventId)
                .containsExactly(CONFIG + "-e3", CONFIG + "-e2");
    }

    // --- fixtures ----------------------------------------------------------------------

    private void indexFixtures() {
        // e1 and e3 are flagged repeat offenders; the rest are not.
        save("e1", "203.0.113.7", "INJECTION", Action.DENY, true, "2026-07-10T10:00:00Z");
        save("e2", "203.0.113.7", "INJECTION", Action.ALERT, false, "2026-07-10T10:01:00Z");
        save("e3", "203.0.113.7", "INJECTION", Action.DENY, true, "2026-07-10T10:02:00Z");
        save("e4", "198.51.100.9", "BOT", Action.MONITOR, false, "2026-07-10T10:03:00Z");
        save("e5", "203.0.113.7", "XSS", Action.DENY, false, "2026-07-10T10:04:00Z");
        operations.indexOps(SecurityEventDocument.class).refresh();
    }

    private void save(String id, String ip, String category, Action action,
                      boolean repeatOffender, String ts) {
        storageService.save(new SecurityEvent(
                CONFIG + "-" + id,
                OffsetDateTime.parse(ts),
                CONFIG,
                "policy-1",
                ip,
                "example.com",
                "/login",
                "POST",
                403,
                "curl/8.0",
                512L,
                1024L,
                OffsetDateTime.parse(ts),
                new Rule("r-" + id, "rule", "msg", Severity.HIGH, category, action),
                new GeoLocation("US", "NYC"),
                category,
                80,
                repeatOffender));
    }

    private static boolean elasticsearchReachable() {
        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create("http://localhost:9200").toURL()
                    .openConnection();
            conn.setConnectTimeout(1000);
            conn.setReadTimeout(1000);
            conn.setRequestMethod("GET");
            int code = conn.getResponseCode();
            conn.disconnect();
            return code >= 200 && code < 500;
        } catch (IOException e) {
            return false;
        }
    }
}
