package com.es.wsa.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Web Security Analytics business policies, bound from {@code wsa.policies} in
 * {@code wsa-policies.yml} at startup.
 *
 * <p>The whole security vocabulary is configuration-driven via key-value maps rather
 * than hard-coded enums, so operators can tune categories and the scoring model without
 * a redeploy:
 * <ul>
 *   <li>{@code categories} — canonical category key → human-readable display name. The
 *       <em>keys</em> form the authoritative set of allowed {@code rule.category} values
 *       that {@code SecurityEventValidator} enforces.</li>
 *   <li>{@code severityScores} — severity name → risk score contribution.</li>
 *   <li>{@code actionScores} — action name → risk score contribution.</li>
 * </ul>
 *
 * <p>Lookups are case-insensitive: map keys are normalised to upper case once at
 * construction time and callers normalise the same way.
 */
@ConfigurationProperties(prefix = "wsa.policies")
public class WsaPolicyProperties {

    private final Map<String, String> categories;
    private final Map<String, Integer> severityScores;
    private final Map<String, Integer> actionScores;

    /** Precomputed upper-cased category keys, for case-insensitive membership checks. */
    private final Set<String> normalisedCategoryKeys;

    public WsaPolicyProperties(Map<String, String> categories,
                               Map<String, Integer> severityScores,
                               Map<String, Integer> actionScores) {
        this.categories = categories == null ? Map.of() : Map.copyOf(categories);
        this.severityScores = severityScores == null ? Map.of() : Map.copyOf(severityScores);
        this.actionScores = actionScores == null ? Map.of() : Map.copyOf(actionScores);
        this.normalisedCategoryKeys = this.categories.keySet().stream()
                .filter(k -> k != null && !k.isBlank())
                .map(WsaPolicyProperties::normalise)
                .collect(Collectors.toUnmodifiableSet());
    }

    /** @return category key → display name */
    public Map<String, String> getCategories() {
        return categories;
    }

    /** @return severity name → risk score */
    public Map<String, Integer> getSeverityScores() {
        return severityScores;
    }

    /** @return action name → risk score */
    public Map<String, Integer> getActionScores() {
        return actionScores;
    }

    /**
     * Tests whether the given category is one of the configured category keys,
     * ignoring case and surrounding whitespace.
     *
     * @param category the category to check; {@code null}/blank is never allowed
     * @return {@code true} if {@code category} matches a configured category key
     */
    public boolean isAllowedCategory(String category) {
        if (category == null || category.isBlank()) {
            return false;
        }
        return normalisedCategoryKeys.contains(normalise(category));
    }

    /**
     * @return the display name for a category key (case-insensitive), or {@code null}
     * if the category is not configured
     */
    public String displayNameFor(String category) {
        if (category == null || category.isBlank()) {
            return null;
        }
        String target = normalise(category);
        return categories.entrySet().stream()
                .filter(e -> normalise(e.getKey()).equals(target))
                .map(Map.Entry::getValue)
                .findFirst()
                .orElse(null);
    }

    /** @return the configured allowed category keys (as declared) */
    public Set<String> categoryKeys() {
        return categories.keySet();
    }

    /**
     * Looks up the risk score for a severity name (case-insensitive).
     *
     * @param severity severity name
     * @return the configured score, or {@code 0} if unknown
     */
    public int severityScore(String severity) {
        return scoreFrom(severityScores, severity);
    }

    /**
     * Looks up the risk score for an action name (case-insensitive).
     *
     * @param action action name
     * @return the configured score, or {@code 0} if unknown
     */
    public int actionScore(String action) {
        return scoreFrom(actionScores, action);
    }

    private static int scoreFrom(Map<String, Integer> scores, String key) {
        if (key == null || key.isBlank()) {
            return 0;
        }
        String target = normalise(key);
        return scores.entrySet().stream()
                .filter(e -> normalise(e.getKey()).equals(target))
                .map(Map.Entry::getValue)
                .findFirst()
                .orElse(0);
    }

    private static String normalise(String value) {
        return value.trim().toUpperCase(Locale.ROOT);
    }
}
