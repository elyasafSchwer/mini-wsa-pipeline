package com.es.wsa.stats;

import com.es.wsa.domain.Action;
import com.es.wsa.domain.GeoLocation;
import com.es.wsa.domain.Rule;
import com.es.wsa.domain.SecurityEvent;
import com.es.wsa.domain.Severity;
import com.es.wsa.standalone.InMemoryEventStore;
import com.es.wsa.storage.EventStorageService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test for the stats aggregation path, run under the fully in-memory
 * {@code standalone} profile — no Elasticsearch, no Docker. Proves the aggregation logic and
 * the aggregate-result mapping (byCategory/byAction/topAttackers/topTargetedPaths, averages,
 * zero-filled time buckets) that cannot be exercised with mocks.
 *
 * <p>Fixtures are written through the real {@link EventStorageService} → store path (so the
 * exercised document mapping is the one the app actually uses), and the shared
 * {@link InMemoryEventStore} is cleared before each test for isolation.
 */
@SpringBootTest
@ActiveProfiles("standalone")
class StatsAggregationTests {

    /** "UNKNOWN" missing-value bucket sentinel — asserted directly to stay impl-agnostic. */
    private static final String UNKNOWN = "UNKNOWN";

    private static final long CONFIG = 900_000_000L;

    @Autowired
    private EventStorageService storageService;

    @Autowired
    private StatsService statsService;

    @Autowired
    private InMemoryEventStore store;

    @BeforeEach
    void seed() {
        store.clear();
        indexFixtures();
    }

    @Test
    void summarizesWithinRange() {
        StatsQuery query = new StatsQuery(
                CONFIG,
                java.time.OffsetDateTime.parse("2026-07-01T00:00:00Z"),
                java.time.OffsetDateTime.parse("2026-07-31T23:59:59Z"));

        StatsSummaryResponse summary = statsService.summarize(query);

        // a1..a5 match; a-old (out of range) is excluded by the time filter.
        assertThat(summary.totalEvents()).isEqualTo(5);
        assertThat(summary.configId()).isEqualTo(CONFIG);

        // byCategory: INJECTION x3 (avg 90.0), BOT x1 (avg 40.0), UNKNOWN x1 (avg 10.0).
        assertThat(summary.byCategory()).containsKeys("INJECTION", "BOT", UNKNOWN);
        assertThat(summary.byCategory().get("INJECTION").count()).isEqualTo(3);
        assertThat(summary.byCategory().get("INJECTION").avgThreatScore()).isEqualTo(90.0);
        assertThat(summary.byCategory().get("BOT").count()).isEqualTo(1);
        assertThat(summary.byCategory().get(UNKNOWN).count()).isEqualTo(1);

        // byAction: DENY x3, ALERT x1, MONITOR x1.
        assertThat(summary.byAction()).containsEntry("DENY", 3L)
                .containsEntry("ALERT", 1L)
                .containsEntry("MONITOR", 1L);

        // topAttackers ordered by count desc: .42 (3) before .7 (2).
        assertThat(summary.topAttackers()).hasSize(2);
        assertThat(summary.topAttackers().get(0).clientIp()).isEqualTo("203.0.113.42");
        assertThat(summary.topAttackers().get(0).count()).isEqualTo(3);
        assertThat(summary.topAttackers().get(0).avgThreatScore()).isEqualTo(90.0);
        assertThat(summary.topAttackers().get(1).clientIp()).isEqualTo("198.51.100.7");

        // topTargetedPaths ordered by count desc: /api/v1/login (3) is the most targeted.
        assertThat(summary.topTargetedPaths().get(0).path()).isEqualTo("/api/v1/login");
        assertThat(summary.topTargetedPaths().get(0).count()).isEqualTo(3);

        // overall avg of 80,90,100,40,10 = 64.0.
        assertThat(summary.avgThreatScore()).isEqualTo(64.0);
    }

    @Test
    void excludesOutOfRangeEvents() {
        // Narrow the range to exclude everything: our fixtures are all in July 2026.
        StatsQuery query = new StatsQuery(
                CONFIG,
                java.time.OffsetDateTime.parse("2000-01-01T00:00:00Z"),
                java.time.OffsetDateTime.parse("2000-01-02T00:00:00Z"));

        StatsSummaryResponse summary = statsService.summarize(query);

        assertThat(summary.totalEvents()).isZero();
        assertThat(summary.byCategory()).isEmpty();
        assertThat(summary.avgThreatScore()).isEqualTo(0.0);
    }

    @Test
    void timeseriesBucketsByHourWithZeroFilledGaps() {
        // a1/a2/a3 are on 2026-07-10 at 10:00, 11:00, 12:00. Ask for hourly buckets over
        // 10:00-13:00 -> four 1h buckets: 10h=1, 11h=1, 12h=1, 13h=0 (zero-filled gap).
        StatsQuery query = new StatsQuery(
                CONFIG,
                java.time.OffsetDateTime.parse("2026-07-10T10:00:00Z"),
                java.time.OffsetDateTime.parse("2026-07-10T13:00:00Z"));

        TimeSeriesResponse series = statsService.timeseries(query, TimeInterval.H1);

        assertThat(series.configId()).isEqualTo(CONFIG);
        assertThat(series.interval()).isEqualTo("1h");
        // extended_bounds [10:00, 13:00] with min_doc_count=0 -> four contiguous buckets.
        assertThat(series.buckets()).hasSize(4);
        assertThat(series.buckets()).extracting(TimeSeriesResponse.Bucket::count)
                .containsExactly(1L, 1L, 1L, 0L);
        // Total across buckets equals the in-range event count.
        long total = series.buckets().stream().mapToLong(TimeSeriesResponse.Bucket::count).sum();
        assertThat(total).isEqualTo(3);
    }

    // --- fixtures ----------------------------------------------------------------------

    private void indexFixtures() {
        // Three INJECTION/DENY from the same busy IP (scores 80/90/100 -> avg 90.0).
        save("a1", "203.0.113.42", "/api/v1/login", "INJECTION", Action.DENY, 80, "2026-07-10T10:00:00Z");
        save("a2", "203.0.113.42", "/api/v1/login", "INJECTION", Action.DENY, 90, "2026-07-10T11:00:00Z");
        save("a3", "203.0.113.42", "/admin", "INJECTION", Action.DENY, 100, "2026-07-10T12:00:00Z");
        // One BOT/ALERT from another IP (score 40).
        save("a4", "198.51.100.7", "/api/v1/login", "BOT", Action.ALERT, 40, "2026-07-11T09:00:00Z");
        // One MONITOR with NO category -> UNKNOWN bucket (score 10).
        saveNoCategory("a5", "198.51.100.7", "/health", Action.MONITOR, 10, "2026-07-11T09:30:00Z");
        // Out of range (July 2025) -> excluded by the July-2026 time filter.
        save("a-old", "203.0.113.42", "/api/v1/login", "INJECTION", Action.DENY, 100, "2025-07-10T10:00:00Z");
    }

    private void save(String id, String ip, String path, String category,
                      Action action, int score, String ts) {
        storageService.save(event(id, ip, path,
                new Rule("r-" + id, "rule", "msg", Severity.HIGH, category, action), score, ts));
    }

    private void saveNoCategory(String id, String ip, String path,
                                Action action, int score, String ts) {
        storageService.save(event(id, ip, path,
                new Rule("r-" + id, "rule", "msg", Severity.LOW, null, action), score, ts));
    }

    private SecurityEvent event(String id, String ip, String path,
                                Rule rule, int score, String ts) {
        return new SecurityEvent(
                CONFIG + "-" + id,
                java.time.OffsetDateTime.parse(ts),
                CONFIG,
                "policy-1",
                ip,
                "example.com",
                path,
                "POST",
                403,
                "curl/8.0",
                512L,
                1024L,
                java.time.OffsetDateTime.parse(ts),
                rule,
                new GeoLocation("US", "NYC"),
                rule.category(),
                score,
                false);
    }
}
