package com.es.wsa.config;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link WsaPolicyProperties} — the map-based lookups and case-insensitive
 * matching used by validation and (later) scoring.
 */
class WsaPolicyPropertiesTest {

    private final WsaPolicyProperties policies = new WsaPolicyProperties(
            Map.of("INJECTION", "SQL/Command Injection", "XSS", "Cross-Site Scripting"),
            Map.of("CRITICAL", 40, "HIGH", 30, "MEDIUM", 20, "LOW", 10),
            Map.of("DENY", 20, "ALERT", 10, "MONITOR", 0));

    @Test
    void allowsConfiguredCategoryKeyCaseInsensitively() {
        assertThat(policies.isAllowedCategory("INJECTION")).isTrue();
        assertThat(policies.isAllowedCategory("injection")).isTrue();
        assertThat(policies.isAllowedCategory("  Xss  ")).isTrue();
    }

    @Test
    void rejectsUnknownOrBlankCategory() {
        assertThat(policies.isAllowedCategory("FOOBAR")).isFalse();
        assertThat(policies.isAllowedCategory("")).isFalse();
        assertThat(policies.isAllowedCategory(null)).isFalse();
    }

    @Test
    void resolvesDisplayName() {
        assertThat(policies.displayNameFor("injection")).isEqualTo("SQL/Command Injection");
        assertThat(policies.displayNameFor("nope")).isNull();
    }

    @Test
    void resolvesSeverityAndActionScores() {
        assertThat(policies.severityScore("CRITICAL")).isEqualTo(40);
        assertThat(policies.severityScore("low")).isEqualTo(10);
        assertThat(policies.actionScore("DENY")).isEqualTo(20);
        assertThat(policies.actionScore("MONITOR")).isEqualTo(0);
    }

    @Test
    void unknownScoreDefaultsToZero() {
        assertThat(policies.severityScore("UNKNOWN")).isEqualTo(0);
        assertThat(policies.actionScore(null)).isEqualTo(0);
    }

    @Test
    void nullMapsDefaultToEmpty() {
        WsaPolicyProperties empty = new WsaPolicyProperties(null, null, null);
        assertThat(empty.getCategories()).isEmpty();
        assertThat(empty.getSeverityScores()).isEmpty();
        assertThat(empty.getActionScores()).isEmpty();
        assertThat(empty.isAllowedCategory("INJECTION")).isFalse();
    }
}
