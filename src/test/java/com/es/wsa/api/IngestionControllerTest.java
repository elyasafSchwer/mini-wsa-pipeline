package com.es.wsa.api;

import com.es.wsa.publisher.EventPublisher;
import com.es.wsa.validation.SecurityEventValidator;
import com.es.wsa.validation.ValidationResult;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Web-slice tests for {@link IngestionController}. The validator and publisher are
 * mocked so the tests focus on request parsing, the single-vs-array contract, and the
 * 201/400 outcomes — not on validation rules themselves (covered separately).
 */
@WebMvcTest(IngestionController.class)
class IngestionControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private SecurityEventValidator validator;

    @MockBean
    private EventPublisher publisher;

    private static final String VALID_EVENT_JSON = """
            {
              "eventId": "evt-1",
              "timestamp": "2026-07-22T10:15:30+00:00",
              "configId": 123,
              "policyId": "policy-1",
              "clientIp": "203.0.113.7",
              "hostname": "example.com",
              "path": "/login",
              "method": "POST",
              "statusCode": 403,
              "userAgent": "curl/8.0",
              "requestSize": 512,
              "responseSize": 1024,
              "rule": {
                "id": "rule-99",
                "name": "SQL Injection",
                "message": "blocked SQLi",
                "severity": "CRITICAL",
                "category": "INJECTION",
                "action": "DENY"
              },
              "geoLocation": { "country": "US", "city": "New York" }
            }
            """;

    @Test
    void acceptsSingleValidObject() throws Exception {
        when(validator.validate(any())).thenReturn(ValidationResult.ok());

        mockMvc.perform(post("/v1/events/ingest")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(VALID_EVENT_JSON))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.accepted").value(1));

        verify(publisher, times(1)).publish(any());
    }

    @Test
    void acceptsArrayOfValidObjects() throws Exception {
        when(validator.validate(any())).thenReturn(ValidationResult.ok());

        String array = "[" + VALID_EVENT_JSON + "," + VALID_EVENT_JSON + "]";

        mockMvc.perform(post("/v1/events/ingest")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(array))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.accepted").value(2));

        verify(publisher, times(2)).publish(any());
    }

    @Test
    void rejectsSingleInvalidObject() throws Exception {
        when(validator.validate(any()))
                .thenReturn(ValidationResult.of(List.of("eventId is required")));

        mockMvc.perform(post("/v1/events/ingest")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(VALID_EVENT_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].index").value(0))
                .andExpect(jsonPath("$.errors[0].messages[0]").value("eventId is required"));

        verify(publisher, never()).publish(any());
    }

    @Test
    void rejectsArrayWhenAnyElementInvalid() throws Exception {
        // First event valid, second invalid -> all-or-nothing: nothing published, 400.
        when(validator.validate(any()))
                .thenReturn(ValidationResult.ok())
                .thenReturn(ValidationResult.of(List.of("rule.category 'NOPE' is not an allowed attack category")));

        String array = "[" + VALID_EVENT_JSON + "," + VALID_EVENT_JSON + "]";

        mockMvc.perform(post("/v1/events/ingest")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(array))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].index").value(1));

        verify(publisher, never()).publish(any());
    }

    @Test
    void rejectsMalformedJson() throws Exception {
        mockMvc.perform(post("/v1/events/ingest")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{ this is not valid json "))
                .andExpect(status().isBadRequest());

        verify(publisher, never()).publish(any());
    }

    @Test
    void rejectsEmptyArray() throws Exception {
        mockMvc.perform(post("/v1/events/ingest")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("[]"))
                .andExpect(status().isBadRequest());

        verify(publisher, never()).publish(any());
    }
}
