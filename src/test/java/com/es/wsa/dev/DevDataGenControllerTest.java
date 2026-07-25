package com.es.wsa.dev;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Web-slice tests for {@link DevDataGenController}.
 *
 * <p>The controller constructs the plain {@link SecurityEventGenerator} and
 * {@link IngestionFeeder} internally and the feeder makes a real HTTP call, so the tests
 * point {@code wsa.datagen.ingest-base-url} at a lightweight in-process stub server that
 * accepts the batches. This verifies the full generate -> feed wiring under the {@code dev}
 * profile, and that the route is absent without it.
 */
class DevDataGenControllerTest {

    /** Profile active: the dev-only controller bean exists and serves the route. */
    @WebMvcTest(DevDataGenController.class)
    @ActiveProfiles("dev")
    static class WithDevProfile {

        private static HttpServer stubServer;
        private static final AtomicInteger acceptedTotal = new AtomicInteger();

        @BeforeAll
        static void startStub() throws IOException {
            stubServer = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
            stubServer.createContext("/v1/events/ingest", exchange -> {
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                int count = body.split("\"eventId\"", -1).length - 1;
                acceptedTotal.addAndGet(count);
                byte[] resp = ("{\"accepted\":" + count + ",\"message\":\"ok\"}")
                        .getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(201, resp.length);
                exchange.getResponseBody().write(resp);
                exchange.close();
            });
            stubServer.start();
        }

        @AfterAll
        static void stopStub() {
            stubServer.stop(0);
        }

        @DynamicPropertySource
        static void ingestUrl(DynamicPropertyRegistry registry) {
            registry.add("wsa.datagen.ingest-base-url",
                    () -> "http://localhost:" + stubServer.getAddress().getPort());
        }

        @MockBean
        private com.es.wsa.storage.SecurityEventRepository repository;

        @MockBean
        private org.springframework.data.redis.core.StringRedisTemplate redis;

        @Autowired
        private MockMvc mockMvc;

        @Test
        void runGeneratesAndFeeds() throws Exception {
            // count=120, batchSize default 50 -> 3 batches, 120 events accepted by the stub.
            mockMvc.perform(post("/api/dev/generate").param("count", "120").param("seed", "1"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.generated").value(120))
                    .andExpect(jsonPath("$.feed.totalEvents").value(120))
                    .andExpect(jsonPath("$.feed.accepted").value(120))
                    .andExpect(jsonPath("$.feed.batchesSent").value(3))
                    .andExpect(jsonPath("$.feed.batchesFailed").value(0));
        }

        @Test
        void clearDeletesAllAndReturnsCount() throws Exception {
            org.mockito.Mockito.when(repository.count()).thenReturn(42L);
            org.mockito.Mockito.when(redis.keys(org.mockito.ArgumentMatchers.anyString()))
                    .thenReturn(java.util.Set.of("ip_events:1.2.3.4", "ip_events:5.6.7.8"));
            org.mockito.Mockito.when(redis.delete(org.mockito.ArgumentMatchers.<java.util.Collection<String>>any()))
                    .thenReturn(2L);

            mockMvc.perform(post("/api/dev/clear"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.deletedEvents").value(42))
                    .andExpect(jsonPath("$.deletedRateKeys").value(2));

            verify(repository).deleteAll();
        }

        @Test
        void uploadJsonFileFeeds() throws Exception {
            // Minimal valid JSON event array matching the ingestion schema.
            String json = loadSampleJson();
            MockMultipartFile file = new MockMultipartFile(
                    "file", "events.json", "application/json",
                    json.getBytes(StandardCharsets.UTF_8));

            mockMvc.perform(multipart("/api/dev/upload").file(file))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.generated").isNumber())
                    .andExpect(jsonPath("$.feed.batchesFailed").value(0));
        }

        @Test
        void uploadCsvFileFeeds() throws Exception {
            String csv = loadSampleCsv();
            MockMultipartFile file = new MockMultipartFile(
                    "file", "events.csv", "text/csv",
                    csv.getBytes(StandardCharsets.UTF_8));

            mockMvc.perform(multipart("/api/dev/upload").file(file))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.generated").isNumber())
                    .andExpect(jsonPath("$.feed.batchesFailed").value(0));
        }

        private static String loadSampleJson() throws IOException {
            try (InputStream in = DevDataGenControllerTest.class
                    .getResourceAsStream("/sample-events.json")) {
                if (in != null) {
                    return new String(in.readAllBytes(), StandardCharsets.UTF_8);
                }
            }
            // Minimal inline fallback — one valid event
            return """
                    [{
                      "eventId": "evt-test-001",
                      "timestamp": "2026-01-01T00:00:00Z",
                      "configId": 1,
                      "policyId": "policy-1",
                      "clientIp": "1.2.3.4",
                      "hostname": "example.com",
                      "path": "/api/test",
                      "method": "GET",
                      "statusCode": 200,
                      "rule": {
                        "id": "rule-1",
                        "name": "Test Rule",
                        "message": "test",
                        "severity": "LOW",
                        "category": "sql-injection",
                        "action": "DENY"
                      }
                    }]
                    """;
        }

        private static String loadSampleCsv() {
            return """
                    eventId,timestamp,configId,policyId,clientIp,hostname,path,method,statusCode,userAgent,requestSize,responseSize,rule.id,rule.name,rule.message,rule.severity,rule.category,rule.action,geoLocation.country,geoLocation.city
                    evt-csv-001,2026-01-01T00:00:00Z,1,policy-1,1.2.3.4,example.com,/api/test,GET,200,,,, rule-1,Test Rule,test,LOW,sql-injection,DENY,,
                    """;
        }
    }

    /** No dev profile: the controller bean is absent, so the route 404s. */
    @WebMvcTest(DevDataGenController.class)
    static class WithoutDevProfile {

        @Autowired
        private MockMvc mockMvc;

        @Test
        void routeIsAbsentWithoutDevProfile() throws Exception {
            mockMvc.perform(post("/api/dev/generate"))
                    .andExpect(status().isNotFound());
        }
    }
}
