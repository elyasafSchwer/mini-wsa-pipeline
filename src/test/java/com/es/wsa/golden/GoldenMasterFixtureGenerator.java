package com.es.wsa.golden;

import com.es.wsa.datagen.EventFileReader;
import com.es.wsa.domain.SecurityEvent;
import com.es.wsa.samples.SampleQuery;
import com.es.wsa.samples.SampleResponse;
import com.es.wsa.samples.SamplesService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Comparator;
import java.util.List;

import static org.awaitility.Awaitility.await;

/**
 * ONE-SHOT generator (not part of the normal suite): runs the real pipeline over the fixture
 * and writes the golden expected-output file to src/test/resources/expected-enriched-events.json.
 * Run explicitly with: mvn test -Dtest=GoldenMasterFixtureGenerator -DgenerateGolden=true
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("standalone")
class GoldenMasterFixtureGenerator {

    @LocalServerPort int port;
    @Autowired TestRestTemplate rest;
    @Autowired SamplesService samplesService;
    @Autowired ObjectMapper objectMapper;

    @Test
    void generate() throws Exception {
        if (!Boolean.parseBoolean(System.getProperty("generateGolden", "false"))) {
            return; // no-op unless explicitly requested
        }
        List<SecurityEvent> fixture = new EventFileReader().read(
                Path.of(getClass().getResource("/events.csv").toURI()));

        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.APPLICATION_JSON);
        for (int s = 0; s < fixture.size(); s += 500) {
            List<SecurityEvent> batch = fixture.subList(s, Math.min(s + 500, fixture.size()));
            rest.postForEntity("http://localhost:" + port + "/v1/events/ingest",
                    new HttpEntity<>(objectMapper.writeValueAsString(batch), h), String.class);
        }
        await().atMost(Duration.ofSeconds(60)).pollInterval(Duration.ofMillis(50)).until(() ->
                samplesService.findSamples(new SampleQuery(null, null, null, null, null, null, null, 1, 0)).total()
                        == fixture.size());

        List<SampleResponse.Sample> all = samplesService.findSamples(
                new SampleQuery(null, null, null, null, null, null, null, 20_000, 0)).items().stream()
                .sorted(Comparator.comparing(SampleResponse.Sample::eventId))
                // Null out the non-deterministic server-stamped receivedAt.
                .map(x -> new SampleResponse.Sample(x.eventId(), x.timestamp(), x.configId(), x.policyId(),
                        x.clientIp(), x.hostname(), x.path(), x.method(), x.statusCode(), x.ruleCategory(),
                        x.ruleSeverity(), x.ruleAction(), x.attackType(), x.threatScore(), x.repeatOffender(),
                        x.geoCountry(), null))
                .toList();

        ObjectMapper pretty = objectMapper.copy().enable(SerializationFeature.INDENT_OUTPUT);
        Path out = Path.of("src/test/resources/expected-enriched-events.json");
        Files.writeString(out, pretty.writeValueAsString(all));
        System.out.println("WROTE golden file: " + out.toAbsolutePath() + " (" + all.size() + " events)");
    }
}
