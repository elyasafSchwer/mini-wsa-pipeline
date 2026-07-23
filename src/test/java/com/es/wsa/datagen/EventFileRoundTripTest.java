package com.es.wsa.datagen;

import com.es.wsa.domain.Action;
import com.es.wsa.domain.GeoLocation;
import com.es.wsa.domain.Rule;
import com.es.wsa.domain.SecurityEvent;
import com.es.wsa.domain.Severity;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;

import static com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Round-trip tests for {@link EventFileWriter} / {@link EventFileReader}: events written to
 * JSON or CSV and read back must equal the originals — including {@code null} optional
 * fields, which exercise the CSV flatten/un-flatten empty-cell handling.
 *
 * <p>The {@link ObjectMapper} is configured to match Spring Boot's auto-configuration
 * (JavaTimeModule, ISO-8601 dates) so the file bytes match what the app would produce.
 */
class EventFileRoundTripTest {

    private final ObjectMapper objectMapper = JsonMapper.builder()
            .addModule(new JavaTimeModule())
            .disable(WRITE_DATES_AS_TIMESTAMPS)
            .build();
    private final EventCsvMapper csvMapper = new EventCsvMapper();
    private final EventFileWriter writer = new EventFileWriter(objectMapper, csvMapper);
    private final EventFileReader reader = new EventFileReader(objectMapper, csvMapper);

    private static final OffsetDateTime TS =
            OffsetDateTime.of(2026, 7, 22, 10, 15, 30, 0, ZoneOffset.UTC);

    private SecurityEvent fullEvent() {
        return new SecurityEvent(
                "evt-1", TS, 123L, "policy-1", "203.0.113.7", "example.com", "/login",
                "POST", 403, "curl/8.0", 512L, 1024L, null,
                new Rule("rule-99", "SQL Injection", "blocked SQLi",
                        Severity.CRITICAL, "INJECTION", Action.DENY),
                new GeoLocation("US", "New York"), null, null, false);
    }

    /** Optional fields null: userAgent, sizes, rule.message, whole geoLocation. */
    private SecurityEvent sparseEvent() {
        return new SecurityEvent(
                "evt-2", TS, 456L, "policy-2", "198.51.100.4", "api.example.com", "/home",
                "GET", 200, null, null, null, null,
                new Rule("rule-1", "Bot", null, Severity.LOW, "BOT", Action.MONITOR),
                null, null, null, false);
    }

    @Test
    void jsonRoundTripPreservesEvents(@TempDir Path dir) {
        List<SecurityEvent> events = List.of(fullEvent(), sparseEvent());
        Path file = dir.resolve("events.json");

        writer.write(events, file, EventFileFormat.JSON);

        assertThat(reader.read(file)).isEqualTo(events);
    }

    @Test
    void csvRoundTripPreservesEvents(@TempDir Path dir) {
        List<SecurityEvent> events = List.of(fullEvent(), sparseEvent());
        Path file = dir.resolve("events.csv");

        writer.write(events, file, EventFileFormat.CSV);

        assertThat(reader.read(file)).isEqualTo(events);
    }

    @Test
    void csvFlattensNestedFieldsIntoDottedHeader(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("events.csv");
        writer.write(List.of(fullEvent()), file, EventFileFormat.CSV);

        String header = java.nio.file.Files.readAllLines(file).get(0);
        assertThat(header)
                .contains("rule.id").contains("rule.severity").contains("rule.category")
                .contains("geoLocation.country").contains("geoLocation.city");
    }

    @Test
    void formatIsDetectedFromExtension() {
        assertThat(EventFileFormat.fromPath(Path.of("a/b/events.json"))).isEqualTo(EventFileFormat.JSON);
        assertThat(EventFileFormat.fromPath(Path.of("events.CSV"))).isEqualTo(EventFileFormat.CSV);
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> EventFileFormat.fromPath(Path.of("events.txt")));
    }
}
