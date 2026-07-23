package com.es.wsa.enrichment;

import com.es.wsa.config.WsaPolicyProperties;
import com.es.wsa.domain.Action;
import com.es.wsa.domain.GeoLocation;
import com.es.wsa.domain.Rule;
import com.es.wsa.domain.SecurityEvent;
import com.es.wsa.domain.Severity;
import com.es.wsa.ratelimit.IpRateTrackerService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link EnrichmentServiceImpl}.
 *
 * <p>{@link IpRateTrackerService} is mocked with Mockito — no Redis (real or
 * Testcontainers) is involved — so these tests exercise the scoring rules in isolation.
 * Scores come from a {@link WsaPolicyProperties} built with the Module 2 reference
 * numbers (CRITICAL=50, HIGH=30, MEDIUM=20, LOW=10; DENY=20, ALERT=10, MONITOR=0;
 * sensitive-path +15, repeat-offender +15, cap 100).
 */
@ExtendWith(MockitoExtension.class)
class EnrichmentServiceImplTest {

    @Mock
    private IpRateTrackerService rateTracker;

    private EnrichmentServiceImpl enrichmentService;

    @BeforeEach
    void setUp() {
        WsaPolicyProperties policies = new WsaPolicyProperties(
                Map.of(
                        "INJECTION", "SQL/Command Injection",
                        "XSS", "Cross-Site Scripting"),
                Map.of("CRITICAL", 50, "HIGH", 30, "MEDIUM", 20, "LOW", 10),
                Map.of("DENY", 20, "ALERT", 10, "MONITOR", 0));
        // scoring + rate-limit fall back to defaults: +15 / +15 / cap 100.
        enrichmentService = new EnrichmentServiceImpl(policies, rateTracker);
    }

    @Test
    void mapsCategoryToAttackTypeDisplayName() {
        when(rateTracker.recordAndCheckExceeded(anyString(), anyString(), any())).thenReturn(false);

        SecurityEvent enriched = enrichmentService.process(
                event("/api/data", Severity.LOW, Action.MONITOR, "INJECTION"));

        assertThat(enriched.attackType()).isEqualTo("SQL/Command Injection");
    }

    @Test
    void fallsBackToRawCategoryWhenNoDisplayNameConfigured() {
        when(rateTracker.recordAndCheckExceeded(anyString(), anyString(), any())).thenReturn(false);

        SecurityEvent enriched = enrichmentService.process(
                event("/api/data", Severity.LOW, Action.MONITOR, "BOT"));

        assertThat(enriched.attackType()).isEqualTo("BOT");
    }

    @Test
    void computesBaseScoreFromSeverityAndAction() {
        when(rateTracker.recordAndCheckExceeded(anyString(), anyString(), any())).thenReturn(false);

        // HIGH(30) + ALERT(10), non-sensitive path, not repeat offender = 40
        SecurityEvent enriched = enrichmentService.process(
                event("/api/data", Severity.HIGH, Action.ALERT, "XSS"));

        assertThat(enriched.threatScore()).isEqualTo(40);
    }

    @Test
    void addsBonusForAdminPath() {
        when(rateTracker.recordAndCheckExceeded(anyString(), anyString(), any())).thenReturn(false);

        // MEDIUM(20) + MONITOR(0) + /admin(15) = 35
        SecurityEvent enriched = enrichmentService.process(
                event("/admin/settings", Severity.MEDIUM, Action.MONITOR, "XSS"));

        assertThat(enriched.threatScore()).isEqualTo(35);
    }

    @Test
    void addsBonusForLoginPath() {
        when(rateTracker.recordAndCheckExceeded(anyString(), anyString(), any())).thenReturn(false);

        // LOW(10) + ALERT(10) + /login(15) = 35
        SecurityEvent enriched = enrichmentService.process(
                event("/login", Severity.LOW, Action.ALERT, "XSS"));

        assertThat(enriched.threatScore()).isEqualTo(35);
    }

    @Test
    void doesNotAddPathBonusForNonSensitivePath() {
        when(rateTracker.recordAndCheckExceeded(anyString(), anyString(), any())).thenReturn(false);

        // HIGH(30) + DENY(20) = 50, no path bonus
        SecurityEvent enriched = enrichmentService.process(
                event("/api/v1/products", Severity.HIGH, Action.DENY, "XSS"));

        assertThat(enriched.threatScore()).isEqualTo(50);
    }

    @Test
    void addsBonusForRepeatOffender() {
        when(rateTracker.recordAndCheckExceeded(anyString(), anyString(), any())).thenReturn(true);

        // HIGH(30) + ALERT(10) + repeat offender(15) = 55
        SecurityEvent enriched = enrichmentService.process(
                event("/api/data", Severity.HIGH, Action.ALERT, "XSS"));

        assertThat(enriched.threatScore()).isEqualTo(55);
    }

    @Test
    void doesNotAddRepeatOffenderBonusWhenNotExceeded() {
        when(rateTracker.recordAndCheckExceeded(anyString(), anyString(), any())).thenReturn(false);

        // HIGH(30) + ALERT(10) = 40, no repeat-offender bonus
        SecurityEvent enriched = enrichmentService.process(
                event("/api/data", Severity.HIGH, Action.ALERT, "XSS"));

        assertThat(enriched.threatScore()).isEqualTo(40);
    }

    @Test
    void combinesAllBonuses() {
        when(rateTracker.recordAndCheckExceeded(anyString(), anyString(), any())).thenReturn(true);

        // CRITICAL(50) + DENY(20) + /admin(15) + repeat offender(15) = 100
        SecurityEvent enriched = enrichmentService.process(
                event("/admin/login", Severity.CRITICAL, Action.DENY, "INJECTION"));

        assertThat(enriched.threatScore()).isEqualTo(100);
    }

    @Test
    void capsScoreAtOneHundred() {
        when(rateTracker.recordAndCheckExceeded(anyString(), anyString(), any())).thenReturn(true);

        // CRITICAL(50) + DENY(20) + /admin(15) + repeat(15) = 115 -> capped to 100.
        // (/admin/login also contains /login, but the path bonus is applied once.)
        SecurityEvent enriched = enrichmentService.process(
                event("/admin/super/login", Severity.CRITICAL, Action.DENY, "INJECTION"));

        assertThat(enriched.threatScore()).isEqualTo(100);
    }

    @Test
    void consultsRateTrackerWithClientIpEventIdAndEventTime() {
        when(rateTracker.recordAndCheckExceeded(anyString(), anyString(), any())).thenReturn(false);

        enrichmentService.process(event("/api/data", Severity.LOW, Action.MONITOR, "XSS"));

        // clientIp + eventId (idempotent dedup member) + the event's own timestamp
        // (event-time window anchor) must all be passed through.
        verify(rateTracker).recordAndCheckExceeded(
                "203.0.113.7", "evt-1", OffsetDateTime.parse("2026-07-22T10:15:30+00:00"));
    }

    @Test
    void preservesOriginalFields() {
        when(rateTracker.recordAndCheckExceeded(anyString(), anyString(), any())).thenReturn(false);

        SecurityEvent original = event("/api/data", Severity.HIGH, Action.DENY, "XSS");
        SecurityEvent enriched = enrichmentService.process(original);

        assertThat(enriched.eventId()).isEqualTo(original.eventId());
        assertThat(enriched.clientIp()).isEqualTo(original.clientIp());
        assertThat(enriched.rule()).isEqualTo(original.rule());
    }

    /** Builds a valid event varying only the fields relevant to scoring. */
    private static SecurityEvent event(String path, Severity severity, Action action, String category) {
        return new SecurityEvent(
                "evt-1",
                OffsetDateTime.parse("2026-07-22T10:15:30+00:00"),
                123L,
                "policy-1",
                "203.0.113.7",
                "example.com",
                path,
                "POST",
                403,
                "curl/8.0",
                512L,
                1024L,
                OffsetDateTime.parse("2026-07-22T10:15:31+00:00"),
                new Rule("rule-99", "Test Rule", "msg", severity, category, action),
                new GeoLocation("US", "New York"),
                null,
                null,
                false);
    }
}
