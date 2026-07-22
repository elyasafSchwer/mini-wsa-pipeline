package com.es.wsa.stats;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Slice tests for {@link StatsController}: parameter parsing/validation and response shape,
 * with a mocked {@link StatsService} (the aggregation logic itself is covered by
 * {@link StatsAggregationIT}).
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
}
