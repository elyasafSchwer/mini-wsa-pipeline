package com.es.wsa.datagen;

import com.es.wsa.domain.SecurityEvent;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

/**
 * Pushes {@link SecurityEvent}s to the ingestion API ({@code POST /v1/events/ingest}) in
 * batches, over real HTTP.
 *
 * <p>A plain, dependency-light Java class — not a Spring component. It builds its own JDK
 * {@link HttpClient} and owns a Jackson {@link ObjectMapper} (configured to match the
 * server), so it can be constructed and driven directly (see {@link #main(String[])} for
 * standalone file feeding, or the dev-only {@code DevDataGenController} which wires it in).
 *
 * <p>Events are partitioned into chunks of {@code batchSize} (default 50) and each chunk is
 * POSTed as a JSON array. Because the ingestion endpoint is all-or-nothing, a chunk is
 * accepted or rejected as a whole; a rejected or failed chunk is logged and counted but does
 * <em>not</em> abort the remaining chunks, so one bad batch doesn't sink an otherwise good
 * feed.
 */
public class IngestionFeeder {

    private static final Logger log = LoggerFactory.getLogger(IngestionFeeder.class);
    private static final String INGEST_PATH = "/v1/events/ingest";
    static final int DEFAULT_BATCH_SIZE = 50;

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final String baseUrl;
    private final int batchSize;

    /**
     * @param baseUrl   base URL of the running server (e.g. {@code http://localhost:8080})
     * @param batchSize events per ingestion request; values {@code <= 0} fall back to 50
     */
    public IngestionFeeder(String baseUrl, int batchSize) {
        this.baseUrl = stripTrailingSlash(baseUrl);
        this.batchSize = batchSize <= 0 ? DEFAULT_BATCH_SIZE : batchSize;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
        this.objectMapper = DataGenObjectMapper.create();
    }

    /**
     * Feeds all events to the ingestion API in batches.
     *
     * @param events the events to push
     * @return a summary of batches sent, events accepted, and failures
     */
    public FeedResult feed(List<SecurityEvent> events) {
        int batchesSent = 0;
        int batchesFailed = 0;
        int accepted = 0;

        for (int from = 0; from < events.size(); from += batchSize) {
            int to = Math.min(from + batchSize, events.size());
            List<SecurityEvent> batch = events.subList(from, to);
            try {
                int batchAccepted = postBatch(batch);
                accepted += batchAccepted;
                batchesSent++;
                log.debug("Ingested batch [{}, {}) -> accepted {}", from, to, batchAccepted);
            } catch (Exception e) {
                batchesFailed++;
                log.warn("Batch [{}, {}) failed: {}", from, to, e.getMessage());
            }
        }

        FeedResult result = new FeedResult(events.size(), batchesSent, batchesFailed, accepted);
        log.info("Feed complete: {}", result);
        return result;
    }

    /** POSTs one batch and returns the server-reported accepted count. */
    private int postBatch(List<SecurityEvent> batch) throws Exception {
        byte[] body = objectMapper.writeValueAsBytes(batch);
        HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + INGEST_PATH))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() / 100 != 2) {
            throw new IllegalStateException("HTTP " + response.statusCode() + ": " + response.body());
        }

        // Success body is IngestionResponse { accepted, message }; fall back to batch size.
        JsonNode json = objectMapper.readTree(response.body());
        return json.hasNonNull("accepted") ? json.get("accepted").asInt() : batch.size();
    }

    private static String stripTrailingSlash(String url) {
        if (url == null || url.isBlank()) {
            return "http://localhost:8080";
        }
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    /**
     * Standalone entry point: read an event file (JSON or CSV) and feed it to a running
     * server's ingestion API in batches.
     *
     * <p>Usage: {@code IngestionFeeder <file> [baseUrl] [batchSize]}. {@code baseUrl}
     * defaults to {@code http://localhost:8080} and {@code batchSize} to 50. Requires the
     * server to be up.
     *
     * @param args {@code <file> [baseUrl] [batchSize]}
     */
    public static void main(String[] args) {
        if (args.length < 1) {
            throw new IllegalArgumentException("Usage: IngestionFeeder <file> [baseUrl] [batchSize]");
        }
        Path file = Path.of(args[0]);
        String baseUrl = args.length > 1 ? args[1] : "http://localhost:8080";
        int batchSize = args.length > 2 ? Integer.parseInt(args[2]) : DEFAULT_BATCH_SIZE;

        List<SecurityEvent> events = new EventFileReader().read(file);
        FeedResult result = new IngestionFeeder(baseUrl, batchSize).feed(events);
        log.info("Fed {} from {}: {}", events.size(), file.toAbsolutePath(), result);
    }

    /**
     * Outcome of a feed run.
     *
     * @param totalEvents   number of events submitted
     * @param batchesSent   batches that were accepted (2xx)
     * @param batchesFailed batches that were rejected or errored
     * @param accepted      total events accepted by the server across all successful batches
     */
    public record FeedResult(int totalEvents, int batchesSent, int batchesFailed, int accepted) {
    }
}
