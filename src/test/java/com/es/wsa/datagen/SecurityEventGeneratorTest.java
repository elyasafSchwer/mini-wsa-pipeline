package com.es.wsa.datagen;

import com.es.wsa.config.WsaPolicyProperties;
import com.es.wsa.domain.SecurityEvent;
import com.es.wsa.validation.SecurityEventValidator;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SecurityEventGenerator}: determinism, counts, wave clustering, and
 * validator compatibility. Plain JUnit 5 — the generator is a plain class constructed with a
 * category vocabulary (mirroring the reference policy keys).
 */
class SecurityEventGeneratorTest {

    private static final List<String> CATEGORIES = List.of(
            "INJECTION", "XSS", "PROTOCOL_VIOLATION", "DATA_LEAKAGE", "BOT", "DOS", "RATE_LIMIT");

    /** Full policy properties, only needed to build a real validator for compatibility checks. */
    private final WsaPolicyProperties policies = new WsaPolicyProperties(
            Map.of(
                    "INJECTION", "SQL/Command Injection",
                    "XSS", "Cross-Site Scripting",
                    "PROTOCOL_VIOLATION", "Protocol Anomaly",
                    "DATA_LEAKAGE", "Data Exfiltration",
                    "BOT", "Bot Activity",
                    "DOS", "Denial of Service",
                    "RATE_LIMIT", "Rate Limiting"),
            Map.of("CRITICAL", 40, "HIGH", 30, "MEDIUM", 20, "LOW", 10),
            Map.of("DENY", 20, "ALERT", 10, "MONITOR", 0));

    private final SecurityEventGenerator generator = new SecurityEventGenerator(CATEGORIES);

    /** Fixed clock so a given seed reproduces byte-for-byte identical timestamps. */
    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.parse("2026-07-23T12:00:00Z"), ZoneOffset.UTC);

    private final SecurityEventGenerator deterministicGenerator =
            new SecurityEventGenerator(CATEGORIES, FIXED_CLOCK);

    private AttackProfile profile(int total, Long seed) {
        return new AttackProfile(total, 0.30, 25, Duration.ofMinutes(2),
                List.of(14227L, 22841L, 30199L), Duration.ofDays(1), seed);
    }

    @Test
    void generatesExactlyTotalEvents() {
        assertThat(generator.generate(profile(500, 1L))).hasSize(500);
        assertThat(generator.generate(profile(0, 1L))).isEmpty();
    }

    @Test
    void sameSeedProducesIdenticalDataset() {
        List<SecurityEvent> a = deterministicGenerator.generate(profile(300, 42L));
        List<SecurityEvent> b = deterministicGenerator.generate(profile(300, 42L));
        assertThat(a).isEqualTo(b);
    }

    @Test
    void eventsAreOrderedByEventTimestamp() {
        // The dataset must be emitted in chronological (event-time) order so that feed/
        // ingestion order matches event time — this is what keeps the repeat-offender
        // sliding window observing each IP's burst in timestamp order.
        List<SecurityEvent> events = generator.generate(profile(500, 5L));
        assertThat(events).extracting(SecurityEvent::timestamp).isSorted();
    }

    @Test
    void differentSeedProducesDifferentDataset() {
        List<SecurityEvent> a = deterministicGenerator.generate(profile(300, 1L));
        List<SecurityEvent> b = deterministicGenerator.generate(profile(300, 2L));
        assertThat(a).isNotEqualTo(b);
    }

    @Test
    void everyEventPassesTheRealValidator() {
        SecurityEventValidator validator = new SecurityEventValidator(policies);
        List<SecurityEvent> events = generator.generate(profile(1000, 7L));

        assertThat(events).allSatisfy(e ->
                assertThat(validator.validate(e).valid())
                        .as("event %s should be valid", e.eventId())
                        .isTrue());
    }

    @Test
    void generatorLeavesServerAndEnrichmentFieldsUnset() {
        assertThat(generator.generate(profile(200, 3L))).allSatisfy(e -> {
            assertThat(e.receivedAt()).isNull();
            assertThat(e.attackType()).isNull();
            assertThat(e.threatScore()).isNull();
        });
    }

    @Test
    void attackWavesClusterOneIpOnOnePathBeyondRateLimitThreshold() {
        // 400 events, 30% waves = 120 wave events, waveSize 25 -> some IPs far exceed the
        // rate-limit threshold (5). Group by clientIp+path and assert at least one burst.
        List<SecurityEvent> events = generator.generate(profile(400, 11L));

        Map<String, List<SecurityEvent>> byIpAndPath = events.stream()
                .collect(Collectors.groupingBy(e -> e.clientIp() + "|" + e.path()));

        List<SecurityEvent> biggestBurst = byIpAndPath.values().stream()
                .max((x, y) -> Integer.compare(x.size(), y.size()))
                .orElseThrow();

        // A wave clusters at least waveSize-ish events on one IP+path — well past threshold 5.
        assertThat(biggestBurst.size()).isGreaterThan(5);

        // All events in a burst share the same IP and path...
        assertThat(biggestBurst).extracting(SecurityEvent::clientIp).containsOnly(biggestBurst.get(0).clientIp());
        assertThat(biggestBurst).extracting(SecurityEvent::path).containsOnly(biggestBurst.get(0).path());

        // ...and are clustered within (a little over) the wave window.
        OffsetDateTime min = biggestBurst.stream().map(SecurityEvent::timestamp)
                .min(OffsetDateTime::compareTo).orElseThrow();
        OffsetDateTime max = biggestBurst.stream().map(SecurityEvent::timestamp)
                .max(OffsetDateTime::compareTo).orElseThrow();
        assertThat(Duration.between(min, max)).isLessThanOrEqualTo(Duration.ofMinutes(2));
    }

    @Test
    void eventIdsAreUnique() {
        List<SecurityEvent> events = generator.generate(profile(1000, 9L));
        Map<String, SecurityEvent> byId = events.stream()
                .collect(Collectors.toMap(SecurityEvent::eventId, Function.identity(), (a, b) -> a));
        assertThat(byId).hasSize(events.size());
    }
}
