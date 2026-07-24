package com.es.wsa.samples;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Slice tests for {@link SamplesController}: parameter parsing/validation, paging defaults
 * and clamping, and response shape, with a mocked {@link SamplesService}. The query logic
 * itself is covered by {@link SamplesQueryIT}.
 */
@WebMvcTest(SamplesController.class)
class SamplesControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private SamplesService samplesService;

    private SampleResponse oneItem() {
        return new SampleResponse(1L, 20, 0, List.of(new SampleResponse.Sample(
                "evt-1", "2026-07-22T10:15:30Z", 14227L, "policy-1", "203.0.113.7",
                "example.com", "/login", "POST", 403, "INJECTION", "CRITICAL", "DENY",
                "SQL/Command Injection", 80, true, "US", "2026-07-22T10:15:31Z")));
    }

    @Test
    void returnsSamplesJsonForValidRequest() throws Exception {
        when(samplesService.findSamples(any())).thenReturn(oneItem());

        mockMvc.perform(get("/v1/events/samples")
                        .param("configId", "14227")
                        .param("category", "INJECTION"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(1))
                .andExpect(jsonPath("$.limit").value(20))
                .andExpect(jsonPath("$.offset").value(0))
                .andExpect(jsonPath("$.items[0].eventId").value("evt-1"))
                .andExpect(jsonPath("$.items[0].ruleCategory").value("INJECTION"))
                .andExpect(jsonPath("$.items[0].repeatOffender").value(true));
    }

    @Test
    void defaultsLimitTo20AndOffsetTo0() throws Exception {
        when(samplesService.findSamples(any())).thenReturn(oneItem());

        mockMvc.perform(get("/v1/events/samples")).andExpect(status().isOk());

        ArgumentCaptor<SampleQuery> captor = ArgumentCaptor.forClass(SampleQuery.class);
        verify(samplesService).findSamples(captor.capture());
        assertThat(captor.getValue().limit()).isEqualTo(20);
        assertThat(captor.getValue().offset()).isZero();
    }

    @Test
    void clampsLimitToMax100() throws Exception {
        when(samplesService.findSamples(any())).thenReturn(oneItem());

        mockMvc.perform(get("/v1/events/samples").param("limit", "500"))
                .andExpect(status().isOk());

        ArgumentCaptor<SampleQuery> captor = ArgumentCaptor.forClass(SampleQuery.class);
        verify(samplesService).findSamples(captor.capture());
        assertThat(captor.getValue().limit()).isEqualTo(100);
    }

    @Test
    void normalisesCategoryAndActionToUpperCase() throws Exception {
        when(samplesService.findSamples(any())).thenReturn(oneItem());

        mockMvc.perform(get("/v1/events/samples")
                        .param("category", "injection")
                        .param("action", "deny"))
                .andExpect(status().isOk());

        ArgumentCaptor<SampleQuery> captor = ArgumentCaptor.forClass(SampleQuery.class);
        verify(samplesService).findSamples(captor.capture());
        assertThat(captor.getValue().category()).isEqualTo("INJECTION");
        assertThat(captor.getValue().action()).isEqualTo("DENY");
    }

    @Test
    void passesClientIpFilterThroughUnchanged() throws Exception {
        when(samplesService.findSamples(any())).thenReturn(oneItem());

        mockMvc.perform(get("/v1/events/samples").param("clientIp", "203.0.113.42"))
                .andExpect(status().isOk());

        ArgumentCaptor<SampleQuery> captor = ArgumentCaptor.forClass(SampleQuery.class);
        verify(samplesService).findSamples(captor.capture());
        // IPs are case-sensitive/exact — passed through verbatim (not upper-cased).
        assertThat(captor.getValue().clientIp()).isEqualTo("203.0.113.42");
    }

    @Test
    void bindsRepeatOffenderFilter() throws Exception {
        when(samplesService.findSamples(any())).thenReturn(oneItem());

        mockMvc.perform(get("/v1/events/samples").param("repeatOffender", "true"))
                .andExpect(status().isOk());

        ArgumentCaptor<SampleQuery> captor = ArgumentCaptor.forClass(SampleQuery.class);
        verify(samplesService).findSamples(captor.capture());
        assertThat(captor.getValue().repeatOffender()).isTrue();
    }

    @Test
    void repeatOffenderIsNullWhenOmitted() throws Exception {
        when(samplesService.findSamples(any())).thenReturn(oneItem());

        mockMvc.perform(get("/v1/events/samples")).andExpect(status().isOk());

        ArgumentCaptor<SampleQuery> captor = ArgumentCaptor.forClass(SampleQuery.class);
        verify(samplesService).findSamples(captor.capture());
        // Absent -> null means "no filter", distinct from an explicit false.
        assertThat(captor.getValue().repeatOffender()).isNull();
    }

    @Test
    void rejectsNegativeOffset() throws Exception {
        mockMvc.perform(get("/v1/events/samples").param("offset", "-1"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("'offset' must not be negative"));

        verify(samplesService, never()).findSamples(any());
    }

    @Test
    void rejectsZeroLimit() throws Exception {
        mockMvc.perform(get("/v1/events/samples").param("limit", "0"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("'limit' must be at least 1"));

        verify(samplesService, never()).findSamples(any());
    }

    @Test
    void rejectsMalformedFrom() throws Exception {
        mockMvc.perform(get("/v1/events/samples").param("from", "not-a-date"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").exists());

        verify(samplesService, never()).findSamples(any());
    }

    @Test
    void rejectsInvertedRange() throws Exception {
        mockMvc.perform(get("/v1/events/samples")
                        .param("from", "2026-07-22T00:00:00Z")
                        .param("to", "2026-07-01T00:00:00Z"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("'from' must not be after 'to'"));

        verify(samplesService, never()).findSamples(any());
    }
}
