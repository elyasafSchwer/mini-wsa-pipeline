package com.es.wsa.dev;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

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

        @Autowired
        private MockMvc mockMvc;

        @Test
        void runGeneratesAndFeeds() throws Exception {
            // count=120, batchSize default 50 -> 3 batches, 120 events accepted by the stub.
            mockMvc.perform(post("/v1/dev/datagen/run").param("count", "120").param("seed", "1"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.generated").value(120))
                    .andExpect(jsonPath("$.feed.totalEvents").value(120))
                    .andExpect(jsonPath("$.feed.accepted").value(120))
                    .andExpect(jsonPath("$.feed.batchesSent").value(3))
                    .andExpect(jsonPath("$.feed.batchesFailed").value(0));
        }
    }

    /** No dev profile: the controller bean is absent, so the route 404s. */
    @WebMvcTest(DevDataGenController.class)
    static class WithoutDevProfile {

        @Autowired
        private MockMvc mockMvc;

        @Test
        void routeIsAbsentWithoutDevProfile() throws Exception {
            mockMvc.perform(post("/v1/dev/datagen/run"))
                    .andExpect(status().isNotFound());
        }
    }
}
