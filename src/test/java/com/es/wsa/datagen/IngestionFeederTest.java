package com.es.wsa.datagen;

import com.es.wsa.domain.Action;
import com.es.wsa.domain.GeoLocation;
import com.es.wsa.domain.Rule;
import com.es.wsa.domain.SecurityEvent;
import com.es.wsa.domain.Severity;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests {@link IngestionFeeder} batching against a real in-process HTTP server (JDK
 * {@code com.sun.net.httpserver}). Verifies events are POSTed to {@code /v1/events/ingest}
 * in batches of the configured size and that the {@link IngestionFeeder.FeedResult}
 * aggregates accepted counts — including partial failure where one batch is rejected but
 * the rest still go through.
 */
class IngestionFeederTest {

    private HttpServer server;
    private String baseUrl;

    /** Number of "eventId" occurrences in each received batch body, in order of receipt. */
    private final List<Integer> receivedBatchSizes = new CopyOnWriteArrayList<>();

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    /** Starts a server whose /v1/events/ingest handler is provided by the caller. */
    private void startServer(IngestHandler handler) throws IOException {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/v1/events/ingest", exchange -> {
            String body = new String(readAll(exchange.getRequestBody()), StandardCharsets.UTF_8);
            int count = body.split("\"eventId\"", -1).length - 1;
            receivedBatchSizes.add(count);
            String response = handler.handle(count);
            byte[] bytes = response == null ? new byte[0] : response.getBytes(StandardCharsets.UTF_8);
            int status = response == null ? 500 : 201;
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        baseUrl = "http://localhost:" + server.getAddress().getPort();
    }

    private static byte[] readAll(InputStream in) throws IOException {
        try (in) {
            return in.readAllBytes();
        }
    }

    private List<SecurityEvent> events(int n) {
        OffsetDateTime ts = OffsetDateTime.of(2026, 7, 22, 10, 0, 0, 0, ZoneOffset.UTC);
        List<SecurityEvent> list = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            list.add(new SecurityEvent("evt-" + i, ts, 1L, "p", "10.0.0." + (i % 250 + 1),
                    "h", "/login", "POST", 403, "curl", 1L, 1L, null,
                    new Rule("r", "n", "m", Severity.HIGH, "INJECTION", Action.DENY),
                    new GeoLocation("US", "NY"), null, null, false));
        }
        return list;
    }

    @Test
    void splitsIntoBatchesOfFiftyAndAggregatesAccepted() throws IOException {
        // Accept every batch, echoing the received count back as "accepted".
        startServer(count -> "{\"accepted\":" + count + ",\"message\":\"ok\"}");

        IngestionFeeder.FeedResult result = new IngestionFeeder(baseUrl, 50).feed(events(120));

        // 120 events -> batches of 50, 50, 20.
        assertThat(receivedBatchSizes).containsExactly(50, 50, 20);
        assertThat(result.totalEvents()).isEqualTo(120);
        assertThat(result.batchesSent()).isEqualTo(3);
        assertThat(result.batchesFailed()).isZero();
        assertThat(result.accepted()).isEqualTo(120);
    }

    @Test
    void oneFailedBatchDoesNotAbortTheRest() throws IOException {
        // Middle batch (2nd) fails with a 500; the others accept 50 each.
        startServer(new IngestHandler() {
            int n = 0;
            @Override
            public String handle(int count) {
                return (n++ == 1) ? null : "{\"accepted\":50,\"message\":\"ok\"}";
            }
        });

        IngestionFeeder.FeedResult result = new IngestionFeeder(baseUrl, 50).feed(events(150));

        assertThat(receivedBatchSizes).hasSize(3);
        assertThat(result.batchesSent()).isEqualTo(2);
        assertThat(result.batchesFailed()).isEqualTo(1);
        assertThat(result.accepted()).isEqualTo(100);
    }

    /** Server-side handler: given the received batch size, return a JSON body or null to 500. */
    private interface IngestHandler {
        String handle(int count);
    }
}
