package com.es.wsa.standalone;

import com.es.wsa.stats.StatsQuery;
import com.es.wsa.stats.StatsService;
import com.es.wsa.stats.StatsSummaryResponse;
import com.es.wsa.stats.TimeInterval;
import com.es.wsa.stats.TimeSeriesResponse;
import com.es.wsa.storage.SecurityEventDocument;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * In-memory {@link StatsService} for the {@code standalone} profile.
 *
 * <p>Recomputes, over the shared {@link InMemoryEventStore}, exactly what
 * {@code ElasticsearchStatsService} computes with aggregations — same filters, same
 * {@code "UNKNOWN"} missing-value bucketing, same "top 10 by count" leaderboards, same
 * count-descending-then-key-ascending term ordering, and the same one-decimal-place average
 * rounding (with an empty average normalised to {@code 0.0}). Averages, like the ES
 * {@code avg} aggregation, are taken over documents that actually have a {@code threatScore}
 * (nulls are ignored, not treated as zero).
 */
@Service
@Primary
@Profile("standalone")
public class InMemoryStatsService implements StatsService {

    static final String UNKNOWN = "UNKNOWN";
    private static final int TOP_N = 10;

    private final InMemoryEventStore store;

    public InMemoryStatsService(InMemoryEventStore store) {
        this.store = store;
    }

    @Override
    public StatsSummaryResponse summarize(StatsQuery query) {
        List<SecurityEventDocument> docs = filter(query);

        return new StatsSummaryResponse(
                query.configId(),
                new StatsSummaryResponse.TimeRange(format(query.from()), format(query.to())),
                docs.size(),
                byCategory(docs),
                byAction(docs),
                topAttackers(docs),
                topTargetedPaths(docs),
                round(averageThreat(docs)));
    }

    @Override
    public TimeSeriesResponse timeseries(StatsQuery query, TimeInterval interval) {
        List<SecurityEventDocument> docs = filter(query);

        return new TimeSeriesResponse(
                query.configId(),
                new TimeSeriesResponse.TimeRange(format(query.from()), format(query.to())),
                interval.token(),
                buckets(docs, interval, query.from(), query.to()));
    }

    // --- filtering ----------------------------------------------------------------------

    /** Applies the query's configId (equals) and timestamp range (inclusive) filters. */
    private List<SecurityEventDocument> filter(StatsQuery query) {
        return store.all().stream()
                .filter(d -> query.configId() == null || query.configId().equals(d.getConfigId()))
                .filter(d -> withinRange(d.getTimestamp(), query.from(), query.to()))
                .toList();
    }

    private static boolean withinRange(OffsetDateTime ts, OffsetDateTime from, OffsetDateTime to) {
        if (from == null && to == null) {
            return true;
        }
        if (ts == null) {
            return false;
        }
        if (from != null && ts.isBefore(from)) {
            return false;
        }
        return to == null || !ts.isAfter(to);
    }

    // --- summary aggregations -----------------------------------------------------------

    /**
     * Terms breakdown with a nested threat-score average, missing key → {@code "UNKNOWN"},
     * ordered by count desc then key asc, into an insertion-ordered map (matches ES).
     */
    private Map<String, StatsSummaryResponse.CategoryStat> byCategory(List<SecurityEventDocument> docs) {
        Map<String, List<SecurityEventDocument>> grouped =
                groupBy(docs, d -> orUnknown(d.getRuleCategory()));
        Map<String, StatsSummaryResponse.CategoryStat> out = new LinkedHashMap<>();
        orderedByCountDescKeyAsc(grouped).forEach(e -> out.put(
                e.getKey(),
                new StatsSummaryResponse.CategoryStat(
                        e.getValue().size(), round(averageThreat(e.getValue())))));
        return out;
    }

    /** Terms breakdown as plain counts, missing key → {@code "UNKNOWN"}, count-desc/key-asc. */
    private Map<String, Long> byAction(List<SecurityEventDocument> docs) {
        Map<String, List<SecurityEventDocument>> grouped =
                groupBy(docs, d -> orUnknown(d.getRuleAction()));
        Map<String, Long> out = new LinkedHashMap<>();
        orderedByCountDescKeyAsc(grouped).forEach(e -> out.put(e.getKey(), (long) e.getValue().size()));
        return out;
    }

    /**
     * Top {@value #TOP_N} client IPs by event count. No {@code "UNKNOWN"} sentinel — clientIp
     * is a validated-required field, mirroring the ES aggregation's {@code null} missing value.
     */
    private List<StatsSummaryResponse.AttackerStat> topAttackers(List<SecurityEventDocument> docs) {
        Map<String, List<SecurityEventDocument>> grouped =
                groupBy(docs.stream().filter(d -> d.getClientIp() != null).toList(),
                        SecurityEventDocument::getClientIp);
        return orderedByCountDescKeyAsc(grouped).stream()
                .limit(TOP_N)
                .map(e -> new StatsSummaryResponse.AttackerStat(
                        e.getKey(), e.getValue().size(), round(averageThreat(e.getValue()))))
                .toList();
    }

    /** Top {@value #TOP_N} request paths by event count, missing → {@code "UNKNOWN"}. */
    private List<StatsSummaryResponse.PathStat> topTargetedPaths(List<SecurityEventDocument> docs) {
        Map<String, List<SecurityEventDocument>> grouped =
                groupBy(docs, d -> orUnknown(d.getPath()));
        return orderedByCountDescKeyAsc(grouped).stream()
                .limit(TOP_N)
                .map(e -> new StatsSummaryResponse.PathStat(e.getKey(), e.getValue().size()))
                .toList();
    }

    // --- time series --------------------------------------------------------------------

    /**
     * Epoch-aligned fixed-interval buckets over {@code [from, to]}, zero-filled — matching the
     * ES {@code date_histogram} with {@code min_doc_count = 0} and {@code extended_bounds}.
     * Bucket labels are the interval start formatted in UTC (ES {@code strict_date_optional_time}
     * {@code key_as_string}).
     */
    private List<TimeSeriesResponse.Bucket> buckets(
            List<SecurityEventDocument> docs, TimeInterval interval,
            OffsetDateTime from, OffsetDateTime to) {

        long step = stepMillis(interval);
        long start = floorToStep(from.toInstant().toEpochMilli(), step);
        long lastBucket = floorToStep(to.toInstant().toEpochMilli(), step);

        // Count docs into their bucket start.
        Map<Long, Long> counts = new java.util.HashMap<>();
        for (SecurityEventDocument d : docs) {
            if (d.getTimestamp() == null) {
                continue;
            }
            long b = floorToStep(d.getTimestamp().toInstant().toEpochMilli(), step);
            counts.merge(b, 1L, Long::sum);
        }

        List<TimeSeriesResponse.Bucket> out = new ArrayList<>();
        for (long b = start; b <= lastBucket; b += step) {
            out.add(new TimeSeriesResponse.Bucket(formatUtc(b), counts.getOrDefault(b, 0L)));
        }
        return out;
    }

    private static long stepMillis(TimeInterval interval) {
        return switch (interval) {
            case M1 -> 60_000L;
            case M5 -> 300_000L;
            case H1 -> 3_600_000L;
        };
    }

    private static long floorToStep(long epochMillis, long step) {
        return Math.floorDiv(epochMillis, step) * step;
    }

    // --- helpers ------------------------------------------------------------------------

    private static Map<String, List<SecurityEventDocument>> groupBy(
            List<SecurityEventDocument> docs, Function<SecurityEventDocument, String> key) {
        return docs.stream().collect(Collectors.groupingBy(key));
    }

    /** Orders grouped entries by count desc, then key asc — the deterministic ES term order. */
    private static List<Map.Entry<String, List<SecurityEventDocument>>> orderedByCountDescKeyAsc(
            Map<String, List<SecurityEventDocument>> grouped) {
        return grouped.entrySet().stream()
                .sorted(Comparator
                        .<Map.Entry<String, List<SecurityEventDocument>>>comparingInt(e -> e.getValue().size())
                        .reversed()
                        .thenComparing(Map.Entry::getKey))
                .toList();
    }

    /** Mean of the non-null {@code threatScore}s (ES {@code avg} ignores missing values). */
    private static double averageThreat(List<SecurityEventDocument> docs) {
        return docs.stream()
                .map(SecurityEventDocument::getThreatScore)
                .filter(s -> s != null)
                .mapToInt(Integer::intValue)
                .average()
                .orElse(Double.NaN);
    }

    private static String orUnknown(String value) {
        return (value == null || value.isBlank()) ? UNKNOWN : value;
    }

    /** Rounds to one decimal place; NaN/empty → {@code 0.0} (matches ES empty-avg handling). */
    private static double round(double value) {
        if (Double.isNaN(value)) {
            return 0.0;
        }
        return Math.round(value * 10.0) / 10.0;
    }

    private static String format(OffsetDateTime value) {
        return value == null ? null : value.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
    }

    private static String formatUtc(long epochMillis) {
        return OffsetDateTime.ofInstant(Instant.ofEpochMilli(epochMillis), ZoneOffset.UTC)
                .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
    }
}
