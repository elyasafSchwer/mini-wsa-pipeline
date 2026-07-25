package com.es.wsa.standalone;

import com.es.wsa.samples.SampleQuery;
import com.es.wsa.samples.SampleResponse;
import com.es.wsa.samples.SamplesService;
import com.es.wsa.storage.SecurityEventDocument;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;

/**
 * In-memory {@link SamplesService} for the {@code standalone} profile.
 *
 * <p>Applies the same filters as {@code ElasticsearchSamplesService} (configId, clientIp,
 * timestamp range, category, action, repeatOffender), sorts by event {@code timestamp}
 * descending, reports the full match count as {@code total}, and pages with
 * {@code offset}/{@code limit}. Each result is mapped with the same 17-field projection as the
 * ES impl's {@code toSample}.
 *
 * <p><strong>Limitation vs. Elasticsearch:</strong> {@code clientIp} filtering is an exact
 * string match only. The ES {@code ip}-typed term filter additionally accepts CIDR notation
 * (e.g. {@code "203.0.113.0/24"}) for subnet matches; that is not supported in-memory.
 */
@Service
@Primary
@Profile("standalone")
public class InMemorySamplesService implements SamplesService {

    private final InMemoryEventStore store;

    public InMemorySamplesService(InMemoryEventStore store) {
        this.store = store;
    }

    @Override
    public SampleResponse findSamples(SampleQuery query) {
        List<SecurityEventDocument> matches = store.all().stream()
                .filter(d -> query.configId() == null || query.configId().equals(d.getConfigId()))
                .filter(d -> query.clientIp() == null || query.clientIp().equals(d.getClientIp()))
                .filter(d -> withinRange(d.getTimestamp(), query.from(), query.to()))
                .filter(d -> query.category() == null || query.category().equals(d.getRuleCategory()))
                .filter(d -> query.action() == null || query.action().equals(d.getRuleAction()))
                .filter(d -> query.repeatOffender() == null
                        || query.repeatOffender() == d.isRepeatOffender())
                .sorted(byTimestampDesc())
                .toList();

        long total = matches.size();

        List<SampleResponse.Sample> items = matches.stream()
                .skip(query.offset())
                .limit(query.limit())
                .map(InMemorySamplesService::toSample)
                .toList();

        return new SampleResponse(total, query.limit(), query.offset(), items);
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

    /** Newest first; documents with a null timestamp sort last. */
    private static Comparator<SecurityEventDocument> byTimestampDesc() {
        return Comparator.comparing(SecurityEventDocument::getTimestamp,
                Comparator.nullsLast(Comparator.naturalOrder())).reversed();
    }

    /** Mirrors {@code ElasticsearchSamplesService.toSample} (same 17 fields, same order). */
    private static SampleResponse.Sample toSample(SecurityEventDocument d) {
        return new SampleResponse.Sample(
                d.getEventId(),
                format(d.getTimestamp()),
                d.getConfigId(),
                d.getPolicyId(),
                d.getClientIp(),
                d.getHostname(),
                d.getPath(),
                d.getMethod(),
                d.getStatusCode(),
                d.getRuleCategory(),
                d.getRuleSeverity(),
                d.getRuleAction(),
                d.getAttackType(),
                d.getThreatScore(),
                d.isRepeatOffender(),
                d.getGeoCountry(),
                format(d.getReceivedAt()));
    }

    private static String format(OffsetDateTime value) {
        return value == null ? null : value.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
    }
}
