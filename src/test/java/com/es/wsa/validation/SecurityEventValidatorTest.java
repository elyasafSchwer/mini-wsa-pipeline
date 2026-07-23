package com.es.wsa.validation;

import com.es.wsa.config.WsaPolicyProperties;
import com.es.wsa.domain.Action;
import com.es.wsa.domain.GeoLocation;
import com.es.wsa.domain.Rule;
import com.es.wsa.domain.SecurityEvent;
import com.es.wsa.domain.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SecurityEventValidator}. Plain JUnit 5 — no Spring context; the
 * validator is constructed directly with a fixed map-based {@link WsaPolicyProperties}.
 */
class SecurityEventValidatorTest {

    private SecurityEventValidator validator;

    @BeforeEach
    void setUp() {
        WsaPolicyProperties policies = new WsaPolicyProperties(
                Map.of(
                        "INJECTION", "SQL/Command Injection",
                        "XSS", "Cross-Site Scripting",
                        "BOT", "Bot Activity",
                        "DOS", "Denial of Service"),
                Map.of("CRITICAL", 40, "HIGH", 30, "MEDIUM", 20, "LOW", 10),
                Map.of("DENY", 20, "ALERT", 10, "MONITOR", 0));
        validator = new SecurityEventValidator(policies);
    }

    @Test
    void acceptsFullyValidEvent() {
        ValidationResult result = validator.validate(validEvent());

        assertThat(result.valid()).isTrue();
        assertThat(result.errors()).isEmpty();
    }

    @Test
    void rejectsNullEvent() {
        ValidationResult result = validator.validate(null);

        assertThat(result.valid()).isFalse();
        assertThat(result.errors()).containsExactly("event must not be null");
    }

    @Test
    void reportsMissingRequiredTopLevelField() {
        SecurityEvent event = validEvent().withEventId(null);

        ValidationResult result = validator.validate(event);

        assertThat(result.valid()).isFalse();
        assertThat(result.errors()).contains("eventId is required");
    }

    @Test
    void reportsMissingRule() {
        SecurityEvent event = validEvent().withRule(null);

        ValidationResult result = validator.validate(event);

        assertThat(result.valid()).isFalse();
        assertThat(result.errors()).contains("rule is required");
    }

    @Test
    void reportsMissingRuleSubField() {
        SecurityEvent event = validEvent().withRule(
                new Rule(null, "SQLi", "msg", Severity.CRITICAL, "INJECTION", Action.DENY));

        ValidationResult result = validator.validate(event);

        assertThat(result.valid()).isFalse();
        assertThat(result.errors()).contains("rule.id is required");
    }

    @Test
    void rejectsUnknownCategory() {
        SecurityEvent event = validEvent().withRule(
                new Rule("r-1", "Weird", "msg", Severity.LOW, "FOOBAR", Action.ALERT));

        ValidationResult result = validator.validate(event);

        assertThat(result.valid()).isFalse();
        assertThat(result.errors())
                .anyMatch(e -> e.contains("FOOBAR") && e.contains("not an allowed attack category"));
    }

    @Test
    void rejectsBlankCategory() {
        SecurityEvent event = validEvent().withRule(
                new Rule("r-1", "Blank", "msg", Severity.LOW, "  ", Action.ALERT));

        ValidationResult result = validator.validate(event);

        assertThat(result.valid()).isFalse();
        assertThat(result.errors()).contains("rule.category is required");
    }

    @Test
    void matchesCategoryCaseInsensitively() {
        SecurityEvent event = validEvent().withRule(
                new Rule("r-1", "SQLi", "msg", Severity.HIGH, "injection", Action.DENY));

        ValidationResult result = validator.validate(event);

        assertThat(result.valid()).isTrue();
    }

    @Test
    void accumulatesMultipleErrors() {
        SecurityEvent event = new SecurityEvent(
                null, null, null, "policy-1", null, null, null, null, null,
                "ua", 10L, 20L, null,
                new Rule("r-1", "SQLi", "msg", Severity.HIGH, "NOPE", Action.DENY),
                new GeoLocation("US", "NYC"),
                null, null, false);

        ValidationResult result = validator.validate(event);

        assertThat(result.valid()).isFalse();
        // eventId, timestamp, configId, clientIp, hostname, path, method, statusCode, bad category
        assertThat(result.errors()).hasSizeGreaterThanOrEqualTo(9);
        assertThat(result.errors()).contains(
                "eventId is required", "timestamp is required", "configId is required",
                "clientIp is required", "hostname is required", "path is required",
                "method is required", "statusCode is required");
    }

    private static SecurityEvent validEvent() {
        return new SecurityEvent(
                "evt-1",
                OffsetDateTime.parse("2026-07-22T10:15:30+00:00"),
                123L,
                "policy-1",
                "203.0.113.7",
                "example.com",
                "/login",
                "POST",
                403,
                "curl/8.0",
                512L,
                1024L,
                null,
                new Rule("rule-99", "SQL Injection", "blocked SQLi", Severity.CRITICAL, "INJECTION", Action.DENY),
                new GeoLocation("US", "New York"),
                null, null, false);
    }
}
