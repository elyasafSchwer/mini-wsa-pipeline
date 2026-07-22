package com.es.wsa.stats;

import co.elastic.clients.elasticsearch._types.aggregations.Aggregation;
import co.elastic.clients.elasticsearch._types.aggregations.StringTermsBucket;
import co.elastic.clients.elasticsearch._types.query_dsl.BoolQuery;
import co.elastic.clients.elasticsearch._types.query_dsl.Query;
import co.elastic.clients.json.JsonData;
import com.es.wsa.storage.SecurityEventDocument;
import org.springframework.data.elasticsearch.client.elc.ElasticsearchAggregation;
import org.springframework.data.elasticsearch.client.elc.ElasticsearchAggregations;
import org.springframework.data.elasticsearch.client.elc.NativeQuery;
import org.springframework.data.elasticsearch.core.ElasticsearchOperations;
import org.springframework.data.elasticsearch.core.SearchHits;
import org.springframework.data.elasticsearch.core.AggregationsContainer;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * {@link StatsService} backed by Elasticsearch aggregations.
 *
 * <p>Builds a single {@code size=0} search against the {@code security-events} index that
 * carries a bool filter (configId term + timestamp range, as present) and five
 * aggregations, then maps the returned aggregate tree onto {@link StatsSummaryResponse}.
 * Because everything is computed in one round-trip and no documents are returned, the cost
 * is independent of how many events match.
 *
 * <h2>Missing-value handling</h2>
 * Every terms aggregation uses {@code missing("UNKNOWN")} so events lacking a category,
 * action, client IP or path still appear in their breakdown under an {@code "UNKNOWN"}
 * bucket — keeping the bucket counts reconcilable with {@code totalEvents}.
 */
@Service
public class ElasticsearchStatsService implements StatsService {

    /** Sentinel bucket key for documents missing the aggregated field. */
    static final String UNKNOWN = "UNKNOWN";

    /** Top-N size for the attacker/path leaderboards. */
    private static final int TOP_N = 10;

    // Aggregation names (kept as constants so build and read sites cannot drift apart).
    private static final String AGG_BY_CATEGORY = "by_category";
    private static final String AGG_BY_ACTION = "by_action";
    private static final String AGG_TOP_ATTACKERS = "top_attackers";
    private static final String AGG_TOP_PATHS = "top_paths";
    private static final String AGG_AVG_THREAT = "avg_threat";
    /** Name of the avg-threat-score sub-aggregation nested inside a terms bucket. */
    private static final String SUB_AVG_THREAT = "bucket_avg_threat";

    private final ElasticsearchOperations operations;

    public ElasticsearchStatsService(ElasticsearchOperations operations) {
        this.operations = operations;
    }

    @Override
    public StatsSummaryResponse summarize(StatsQuery query) {
        NativeQuery nativeQuery = NativeQuery.builder()
                .withQuery(buildFilter(query))
                .withAggregation(AGG_BY_CATEGORY, termsWithAvgThreat("ruleCategory", UNKNOWN))
                .withAggregation(AGG_BY_ACTION, terms("ruleAction", Integer.MAX_VALUE, UNKNOWN))
                // clientIp is an `ip`-typed field; ES rejects a non-IP `missing` sentinel on
                // it. clientIp is a validated-required field, so missing values never reach
                // the index — no sentinel is needed.
                .withAggregation(AGG_TOP_ATTACKERS, termsWithAvgThreat("clientIp", TOP_N, null))
                .withAggregation(AGG_TOP_PATHS, terms("path.keyword", TOP_N, UNKNOWN))
                .withAggregation(AGG_AVG_THREAT, avg("threatScore"))
                .withMaxResults(0)
                .build();

        SearchHits<SecurityEventDocument> hits =
                operations.search(nativeQuery, SecurityEventDocument.class);

        Map<String, co.elastic.clients.elasticsearch._types.aggregations.Aggregate> aggs =
                toAggregateMap(hits.getAggregations());

        return new StatsSummaryResponse(
                query.configId(),
                new StatsSummaryResponse.TimeRange(format(query.from()), format(query.to())),
                hits.getTotalHits(),
                mapCategories(aggs.get(AGG_BY_CATEGORY)),
                mapActions(aggs.get(AGG_BY_ACTION)),
                mapAttackers(aggs.get(AGG_TOP_ATTACKERS)),
                mapPaths(aggs.get(AGG_TOP_PATHS)),
                round(aggs.get(AGG_AVG_THREAT).avg().value()));
    }

    // --- query construction -------------------------------------------------------------

    /**
     * Builds the bool filter from the query: a {@code configId} term and/or a
     * {@code timestamp} range as each is present. With neither set, matches everything.
     */
    private Query buildFilter(StatsQuery query) {
        BoolQuery.Builder bool = new BoolQuery.Builder();
        boolean any = false;

        if (query.configId() != null) {
            bool.filter(f -> f.term(t -> t.field("configId").value(query.configId())));
            any = true;
        }
        if (query.from() != null || query.to() != null) {
            bool.filter(f -> f.range(r -> {
                r.field("timestamp");
                // The timestamp field is mapped with the strict `date_time` format, which
                // requires milliseconds; incoming ISO-8601 bounds may omit them
                // (e.g. "2026-07-01T00:00:00Z"). Parse the bounds with the lenient
                // `strict_date_optional_time` format so both forms are accepted.
                r.format("strict_date_optional_time");
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

        if (!any) {
            return Query.of(q -> q.matchAll(m -> m));
        }
        return Query.of(q -> q.bool(bool.build()));
    }

    private Aggregation terms(String field, int size, String missing) {
        // Terms aggregations default to ordering buckets by descending doc_count, which is
        // exactly the "top by event count" ordering the leaderboards need.
        return Aggregation.of(a -> a.terms(t -> {
            t.field(field).size(size);
            if (missing != null) {
                t.missing(missing);
            }
            return t;
        }));
    }

    /** A terms aggregation on {@code field} with a nested avg(threatScore) per bucket. */
    private Aggregation termsWithAvgThreat(String field, String missing) {
        return termsWithAvgThreat(field, Integer.MAX_VALUE, missing);
    }

    private Aggregation termsWithAvgThreat(String field, int size, String missing) {
        return Aggregation.of(a -> a
                .terms(t -> {
                    t.field(field).size(size);
                    if (missing != null) {
                        t.missing(missing);
                    }
                    return t;
                })
                .aggregations(SUB_AVG_THREAT, avg("threatScore")));
    }

    private Aggregation avg(String field) {
        return Aggregation.of(a -> a.avg(av -> av.field(field)));
    }

    // --- aggregation result mapping -----------------------------------------------------

    @SuppressWarnings("unchecked")
    private Map<String, co.elastic.clients.elasticsearch._types.aggregations.Aggregate>
    toAggregateMap(AggregationsContainer<?> container) {
        // Spring Data ES wraps the elastic-clients aggregates; unwrap to the raw map so we
        // can read strongly-typed sterms()/avg() views below.
        ElasticsearchAggregations wrapper = (ElasticsearchAggregations) container;
        Map<String, co.elastic.clients.elasticsearch._types.aggregations.Aggregate> result =
                new LinkedHashMap<>();
        for (ElasticsearchAggregation agg : wrapper.aggregations()) {
            result.put(agg.aggregation().getName(), agg.aggregation().getAggregate());
        }
        return result;
    }

    private Map<String, StatsSummaryResponse.CategoryStat> mapCategories(
            co.elastic.clients.elasticsearch._types.aggregations.Aggregate agg) {
        Map<String, StatsSummaryResponse.CategoryStat> out = new LinkedHashMap<>();
        for (StringTermsBucket bucket : agg.sterms().buckets().array()) {
            double avg = bucket.aggregations().get(SUB_AVG_THREAT).avg().value();
            out.put(bucket.key().stringValue(),
                    new StatsSummaryResponse.CategoryStat(bucket.docCount(), round(avg)));
        }
        return out;
    }

    private Map<String, Long> mapActions(
            co.elastic.clients.elasticsearch._types.aggregations.Aggregate agg) {
        Map<String, Long> out = new LinkedHashMap<>();
        for (StringTermsBucket bucket : agg.sterms().buckets().array()) {
            out.put(bucket.key().stringValue(), bucket.docCount());
        }
        return out;
    }

    private List<StatsSummaryResponse.AttackerStat> mapAttackers(
            co.elastic.clients.elasticsearch._types.aggregations.Aggregate agg) {
        List<StatsSummaryResponse.AttackerStat> out = new ArrayList<>();
        for (StringTermsBucket bucket : agg.sterms().buckets().array()) {
            double avg = bucket.aggregations().get(SUB_AVG_THREAT).avg().value();
            out.add(new StatsSummaryResponse.AttackerStat(
                    bucket.key().stringValue(), bucket.docCount(), round(avg)));
        }
        return out;
    }

    private List<StatsSummaryResponse.PathStat> mapPaths(
            co.elastic.clients.elasticsearch._types.aggregations.Aggregate agg) {
        List<StatsSummaryResponse.PathStat> out = new ArrayList<>();
        for (StringTermsBucket bucket : agg.sterms().buckets().array()) {
            out.add(new StatsSummaryResponse.PathStat(bucket.key().stringValue(), bucket.docCount()));
        }
        return out;
    }

    // --- helpers ------------------------------------------------------------------------

    /**
     * Rounds a threat-score average to one decimal place. An empty bucket yields a
     * {@code NaN} average from Elasticsearch, which we normalise to {@code 0.0}.
     */
    private static double round(Double value) {
        if (value == null || value.isNaN()) {
            return 0.0;
        }
        return Math.round(value * 10.0) / 10.0;
    }

    private static String format(OffsetDateTime value) {
        return value == null ? null : value.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
    }
}
