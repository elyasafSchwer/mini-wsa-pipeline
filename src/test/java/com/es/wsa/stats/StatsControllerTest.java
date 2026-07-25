package com.es.wsa.stats;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Slice tests for {@link StatsController}: parameter parsing/validation and response shape,
 * with a mocked {@link StatsService} (the aggregation logic itself is covered by
 * {@link StatsAggregationTests}).
 */
@WebMvcTest(StatsController.class)
class StatsControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private StatsService statsService;

    @Test
    void returnsSummaryJsonForValidRequest() throws Exception {
        StatsSummaryResponse sample = new StatsSummaryResponse(
                14227L,
                new StatsSummaryResponse.TimeRange("2026-07-01T00:00:00Z", "2026-07-22T00:00:00Z"),
                1523L,
                Map.of("INJECTION", new StatsSummaryResponse.CategoryStat(450L, 72.3)),
                Map.of("DENY", 890L, "ALERT", 433L, "MONITOR", 200L),
                List.of(new StatsSummaryResponse.AttackerStat("203.0.113.42", 87L, 81.2)),
                List.of(new StatsSummaryResponse.PathStat("/api/v1/login", 234L)),
                45.1);
        when(statsService.summarize(any())).thenReturn(sample);

        mockMvc.perform(get("/v1/stats/summary")
                        .param("configId", "14227")
                        .param("from", "2026-07-01T00:00:00Z")
                        .param("to", "2026-07-22T00:00:00Z"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.configId").value(14227))
                .andExpect(jsonPath("$.totalEvents").value(1523))
                .andExpect(jsonPath("$.byCategory.INJECTION.count").value(450))
                .andExpect(jsonPath("$.byCategory.INJECTION.avgThreatScore").value(72.3))
                .andExpect(jsonPath("$.byAction.DENY").value(890))
                .andExpect(jsonPath("$.topAttackers[0].clientIp").value("203.0.113.42"))
                .andExpect(jsonPath("$.topTargetedPaths[0].path").value("/api/v1/login"))
                .andExpect(jsonPath("$.avgThreatScore").value(45.1));
    }

    @Test
    void aggregatesAcrossAllConfigsWhenConfigIdOmitted() throws Exception {
        when(statsService.summarize(any())).thenReturn(empty());

        mockMvc.perform(get("/v1/stats/summary"))
                .andExpect(status().isOk());

        // Service is still invoked; controller does not require any parameter.
        verify(statsService).summarize(any());
    }

    @Test
    void rejectsMalformedFromTimestamp() throws Exception {
        mockMvc.perform(get("/v1/stats/summary").param("from", "not-a-date"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").exists());

        verify(statsService, never()).summarize(any());
    }

    @Test
    void rejectsInvertedRange() throws Exception {
        mockMvc.perform(get("/v1/stats/summary")
                        .param("from", "2026-07-22T00:00:00Z")
                        .param("to", "2026-07-01T00:00:00Z"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("'from' must not be after 'to'"));

        verify(statsService, never()).summarize(any());
    }

    private static StatsSummaryResponse empty() {
        return new StatsSummaryResponse(
                null, new StatsSummaryResponse.TimeRange(null, null), 0L,
                Map.of(), Map.of(), List.of(), List.of(), 0.0);
    }

    // --- timeseries ---------------------------------------------------------------------

    @Test
    void returnsTimeseriesJsonForValidRequest() throws Exception {
        TimeSeriesResponse sample = new TimeSeriesResponse(
                14227L,
                new TimeSeriesResponse.TimeRange("2026-07-22T19:40:00Z", "2026-07-22T19:43:00Z"),
                "1m",
                List.of(
                        new TimeSeriesResponse.Bucket("2026-07-22T19:40:00.000Z", 3L),
                        new TimeSeriesResponse.Bucket("2026-07-22T19:41:00.000Z", 0L),
                        new TimeSeriesResponse.Bucket("2026-07-22T19:42:00.000Z", 5L)));
        when(statsService.timeseries(any(), eq(TimeInterval.M1))).thenReturn(sample);

        mockMvc.perform(get("/v1/stats/timeseries")
                        .param("configId", "14227")
                        .param("from", "2026-07-22T19:40:00Z")
                        .param("to", "2026-07-22T19:43:00Z")
                        .param("interval", "1m"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.configId").value(14227))
                .andExpect(jsonPath("$.interval").value("1m"))
                .andExpect(jsonPath("$.buckets[0].timestamp").value("2026-07-22T19:40:00.000Z"))
                .andExpect(jsonPath("$.buckets[0].count").value(3))
                .andExpect(jsonPath("$.buckets[1].count").value(0));
    }

    @Test
    void defaultsIntervalToOneMinuteWhenOmitted() throws Exception {
        when(statsService.timeseries(any(), eq(TimeInterval.M1))).thenReturn(emptySeries());

        mockMvc.perform(get("/v1/stats/timeseries")
                        .param("from", "2026-07-22T19:40:00Z")
                        .param("to", "2026-07-22T19:50:00Z"))
                .andExpect(status().isOk());

        // Interval defaulted to 1m -> M1 passed to the service.
        verify(statsService).timeseries(any(), eq(TimeInterval.M1));
    }

    @Test
    void rejectsUnknownInterval() throws Exception {
        mockMvc.perform(get("/v1/stats/timeseries")
                        .param("from", "2026-07-22T19:40:00Z")
                        .param("to", "2026-07-22T19:50:00Z")
                        .param("interval", "2m"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").exists());

        verify(statsService, never()).timeseries(any(), any());
    }

    @Test
    void rejectsTimeseriesMissingFromOrTo() throws Exception {
        mockMvc.perform(get("/v1/stats/timeseries").param("to", "2026-07-22T19:50:00Z"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("'from' and 'to' are required for timeseries"));

        verify(statsService, never()).timeseries(any(), any());
    }

    @Test
    void rejectsTimeseriesInvertedRange() throws Exception {
        mockMvc.perform(get("/v1/stats/timeseries")
                        .param("from", "2026-07-22T19:50:00Z")
                        .param("to", "2026-07-22T19:40:00Z"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("'from' must not be after 'to'"));

        verify(statsService, never()).timeseries(any(), any());
    }

    private static TimeSeriesResponse emptySeries() {
        return new TimeSeriesResponse(
                null, new TimeSeriesResponse.TimeRange(null, null), "1m", List.of());
    }
}
