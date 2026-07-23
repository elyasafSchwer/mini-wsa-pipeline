package com.es.wsa.datagen;

import com.es.wsa.domain.Action;
import com.es.wsa.domain.GeoLocation;
import com.es.wsa.domain.Rule;
import com.es.wsa.domain.SecurityEvent;
import com.es.wsa.domain.Severity;
import com.fasterxml.jackson.dataformat.csv.CsvMapper;
import com.fasterxml.jackson.dataformat.csv.CsvSchema;

import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Central definition of the flat CSV representation of a {@link SecurityEvent}, used by
 * both {@link EventFileWriter} and {@link EventFileReader} so the two directions can never
 * disagree on the column set. A plain helper class (not a Spring bean).
 *
 * <p>Nested objects are flattened into dotted top-level columns
 * ({@code rule.id}, {@code rule.severity}, {@code geoLocation.country}, …); scalar fields
 * keep their names. {@link OffsetDateTime}s are written and parsed as ISO-8601 strings to
 * match the JSON representation. Empty cells map to/from {@code null}, so optional fields
 * (userAgent, sizes, geoLocation, …) round-trip cleanly.
 *
 * <p>The generator only produces client-payload fields, so the enrichment/ingestion-owned
 * columns ({@code receivedAt}, {@code attackType}, {@code threatScore}) are intentionally
 * excluded from the CSV schema — the JSON format carries the full structure if those ever
 * need to be captured.
 */
public class EventCsvMapper {

    /** Ordered CSV columns. Nested fields use dotted names; order defines the header. */
    static final String[] COLUMNS = {
            "eventId", "timestamp", "configId", "policyId", "clientIp", "hostname",
            "path", "method", "statusCode", "userAgent", "requestSize", "responseSize",
            "rule.id", "rule.name", "rule.message", "rule.severity", "rule.category", "rule.action",
            "geoLocation.country", "geoLocation.city"
    };

    private final CsvMapper csvMapper = new CsvMapper();

    /** @return the schema (all rows are {@code Map<String,String>} keyed by {@link #COLUMNS}). */
    public CsvSchema schema() {
        CsvSchema.Builder builder = CsvSchema.builder();
        for (String column : COLUMNS) {
            builder.addColumn(column);
        }
        return builder.build().withHeader();
    }

    public CsvMapper csvMapper() {
        return csvMapper;
    }

    /** Flattens an event into an ordered column-keyed row for CSV writing. */
    public Map<String, String> toRow(SecurityEvent event) {
        Map<String, String> row = new LinkedHashMap<>();
        put(row, "eventId", event.eventId());
        put(row, "timestamp", event.timestamp());
        put(row, "configId", event.configId());
        put(row, "policyId", event.policyId());
        put(row, "clientIp", event.clientIp());
        put(row, "hostname", event.hostname());
        put(row, "path", event.path());
        put(row, "method", event.method());
        put(row, "statusCode", event.statusCode());
        put(row, "userAgent", event.userAgent());
        put(row, "requestSize", event.requestSize());
        put(row, "responseSize", event.responseSize());

        Rule rule = event.rule();
        if (rule != null) {
            put(row, "rule.id", rule.id());
            put(row, "rule.name", rule.name());
            put(row, "rule.message", rule.message());
            put(row, "rule.severity", rule.severity());
            put(row, "rule.category", rule.category());
            put(row, "rule.action", rule.action());
        }

        GeoLocation geo = event.geoLocation();
        if (geo != null) {
            put(row, "geoLocation.country", geo.country());
            put(row, "geoLocation.city", geo.city());
        }
        return row;
    }

    /** Rebuilds a nested event from a flat CSV row (blank cells become {@code null}). */
    public SecurityEvent fromRow(Map<String, String> row) {
        Rule rule = new Rule(
                str(row, "rule.id"),
                str(row, "rule.name"),
                str(row, "rule.message"),
                severity(row.get("rule.severity")),
                str(row, "rule.category"),
                action(row.get("rule.action")));

        String country = str(row, "geoLocation.country");
        String city = str(row, "geoLocation.city");
        GeoLocation geo = (country == null && city == null) ? null : new GeoLocation(country, city);

        return new SecurityEvent(
                str(row, "eventId"),
                offsetDateTime(row.get("timestamp")),
                lng(row.get("configId")),
                str(row, "policyId"),
                str(row, "clientIp"),
                str(row, "hostname"),
                str(row, "path"),
                str(row, "method"),
                integer(row.get("statusCode")),
                str(row, "userAgent"),
                lng(row.get("requestSize")),
                lng(row.get("responseSize")),
                null,   // receivedAt — not carried in CSV
                rule,
                geo,
                null,   // attackType — not carried in CSV
                null,   // threatScore — not carried in CSV
                false); // repeatOffender — not carried in CSV
    }

    private static void put(Map<String, String> row, String key, Object value) {
        row.put(key, value == null ? "" : value.toString());
    }

    private static String str(Map<String, String> row, String key) {
        String value = row.get(key);
        return (value == null || value.isEmpty()) ? null : value;
    }

    private static Long lng(String value) {
        return (value == null || value.isBlank()) ? null : Long.parseLong(value.trim());
    }

    private static Integer integer(String value) {
        return (value == null || value.isBlank()) ? null : Integer.parseInt(value.trim());
    }

    private static OffsetDateTime offsetDateTime(String value) {
        return (value == null || value.isBlank()) ? null : OffsetDateTime.parse(value.trim());
    }

    private static Severity severity(String value) {
        return (value == null || value.isBlank()) ? null : Severity.valueOf(value.trim());
    }

    private static Action action(String value) {
        return (value == null || value.isBlank()) ? null : Action.valueOf(value.trim());
    }
}
