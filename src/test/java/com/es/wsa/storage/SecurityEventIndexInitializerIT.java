package com.es.wsa.storage;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.elasticsearch.core.ElasticsearchOperations;
import org.springframework.data.elasticsearch.core.IndexOperations;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Verifies {@link SecurityEventIndexInitializer} pins the annotated mapping: the aggregation
 * fields ({@code ruleCategory}, {@code ruleAction}, {@code clientIp}) must NOT be {@code text}
 * (which would disable the stats terms-aggregations). Self-skipping when ES is unreachable.
 */
@SpringBootTest
class SecurityEventIndexInitializerIT {

    @Autowired
    private ElasticsearchOperations operations;

    @Test
    @SuppressWarnings("unchecked")
    void indexMappingUsesAggregatableTypesNotText() {
        assumeTrue(elasticsearchReachable(),
                "Elasticsearch not reachable on localhost:9200 — skipping index mapping IT.");

        IndexOperations indexOps = operations.indexOps(SecurityEventDocument.class);
        // The initializer (an ApplicationRunner) has already ensured the index exists with
        // the SecurityEventDocument mapping by the time the context is up.
        assertThat(indexOps.exists()).isTrue();

        Map<String, Object> mapping = indexOps.getMapping();
        Map<String, Object> props = (Map<String, Object>) mapping.get("properties");

        // These are the fields the stats terms-aggregations run on; if any is "text", the
        // aggregation fails with "Fielddata is disabled". They must be keyword/ip.
        assertThat(typeOf(props, "ruleCategory")).isEqualTo("keyword");
        assertThat(typeOf(props, "ruleAction")).isEqualTo("keyword");
        assertThat(typeOf(props, "clientIp")).isEqualTo("ip");
        assertThat(typeOf(props, "ruleSeverity")).isEqualTo("keyword");
    }

    @SuppressWarnings("unchecked")
    private static String typeOf(Map<String, Object> props, String field) {
        Object entry = props.get(field);
        assertThat(entry).as("field '%s' present in mapping", field).isInstanceOf(Map.class);
        return String.valueOf(((Map<String, Object>) entry).get("type"));
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
