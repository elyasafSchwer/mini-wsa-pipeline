package com.es.wsa.samples;

import co.elastic.clients.elasticsearch._types.SortOrder;
import co.elastic.clients.elasticsearch._types.query_dsl.BoolQuery;
import co.elastic.clients.elasticsearch._types.query_dsl.Query;
import co.elastic.clients.json.JsonData;
import com.es.wsa.storage.SecurityEventDocument;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.elasticsearch.client.elc.NativeQuery;
import org.springframework.data.elasticsearch.core.ElasticsearchOperations;
import org.springframework.data.elasticsearch.core.SearchHit;
import org.springframework.data.elasticsearch.core.SearchHits;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * {@link SamplesService} backed by Elasticsearch.
 *
 * <p>Builds one filtered search over the {@code security-events} index — a bool filter of
 * the supplied {@code configId} / {@code timestamp} range / {@code category} / {@code action}
 * constraints — sorted by event {@code timestamp} descending, and paged with {@code from} /
 * {@code size} derived from the query's {@code offset} / {@code limit}. The document total
 * ({@code SearchHits.getTotalHits()}) is returned alongside the page so callers can paginate.
 *
 * <p>The filter construction mirrors {@code ElasticsearchStatsService.buildFilter} (same
 * lenient {@code strict_date_optional_time} range format), extended with the category and
 * action term filters this API adds.
 */
@Service
public class ElasticsearchSamplesService implements SamplesService {

    private final ElasticsearchOperations operations;

    public ElasticsearchSamplesService(ElasticsearchOperations operations) {
        this.operations = operations;
    }

    @Override
    public SampleResponse findSamples(SampleQuery query) {
        NativeQuery nativeQuery = NativeQuery.builder()
                .withQuery(buildFilter(query))
                .withSort(s -> s.field(f -> f.field("timestamp").order(SortOrder.Desc)))
                .withPageable(new OffsetLimit(query.offset(), query.limit()))
                // Force an exact total. Elasticsearch otherwise stops counting at 10,000 and
                // returns a lower-bounded (relation "gte") value, which would make the
                // reported total — and thus the client's page count — wrong on large indices.
                .withTrackTotalHits(true)
                .build();

        SearchHits<SecurityEventDocument> hits =
                operations.search(nativeQuery, SecurityEventDocument.class);

        List<SampleResponse.Sample> items = new ArrayList<>(hits.getSearchHits().size());
        for (SearchHit<SecurityEventDocument> hit : hits.getSearchHits()) {
            items.add(toSample(hit.getContent()));
        }

        return new SampleResponse(hits.getTotalHits(), query.limit(), query.offset(), items);
    }

    /**
     * Bool filter from the query: {@code configId} term, {@code timestamp} range, and
     * {@code ruleCategory} / {@code ruleAction} terms — each added only when present. With
     * no constraints, matches everything.
     */
    private Query buildFilter(SampleQuery query) {
        BoolQuery.Builder bool = new BoolQuery.Builder();
        boolean any = false;

        if (query.configId() != null) {
            bool.filter(f -> f.term(t -> t.field("configId").value(query.configId())));
            any = true;
        }
        if (query.from() != null || query.to() != null) {
            bool.filter(f -> f.range(r -> {
                r.field("timestamp").format("strict_date_optional_time");
                if (query.from() != null) {
                    r.gte(JsonData.of(format(query.from())));
                }
                if (query.to() != null) {
                    r.lte(JsonData.of(format(query.to())));
                }
                return r;
            }));
            any = true;
        }
        if (query.category() != null) {
            bool.filter(f -> f.term(t -> t.field("ruleCategory").value(query.category())));
            any = true;
        }
        if (query.action() != null) {
            bool.filter(f -> f.term(t -> t.field("ruleAction").value(query.action())));
            any = true;
        }

        if (!any) {
            return Query.of(q -> q.matchAll(m -> m));
        }
        return Query.of(q -> q.bool(bool.build()));
    }

    private SampleResponse.Sample toSample(SecurityEventDocument d) {
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

    /**
     * A {@link Pageable} carrying an arbitrary {@code offset} (not restricted to a multiple
     * of the page size, which {@code PageRequest} enforces). Spring Data Elasticsearch reads
     * {@link #getOffset()} and {@link #getPageSize()} to set the ES {@code from}/{@code size},
     * which is all this query needs. Navigation methods are unsupported because they are
     * never called on this path.
     */
    private record OffsetLimit(int offset, int limit) implements Pageable {

        @Override
        public boolean isPaged() {
            return true;
        }

        @Override
        public int getPageNumber() {
            return limit == 0 ? 0 : offset / limit;
        }

        @Override
        public int getPageSize() {
            return limit;
        }

        @Override
        public long getOffset() {
            return offset;
        }

        @Override
        public Sort getSort() {
            return Sort.unsorted();
        }

        @Override
        public Pageable next() {
            return new OffsetLimit(offset + limit, limit);
        }

        @Override
        public Pageable previousOrFirst() {
            return new OffsetLimit(Math.max(0, offset - limit), limit);
        }

        @Override
        public Pageable first() {
            return new OffsetLimit(0, limit);
        }

        @Override
        public Pageable withPage(int pageNumber) {
            return new OffsetLimit(pageNumber * limit, limit);
        }

        @Override
        public boolean hasPrevious() {
            return offset > 0;
        }
    }
}
