package com.es.wsa.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;

import java.time.Duration;
import java.util.List;
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
 *   <li>{@code scoring} — threat-scoring tunables (bonuses, cap, sensitive paths).</li>
 *   <li>{@code rateLimit} — sliding-window rate-limit window and threshold.</li>
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
    private final Scoring scoring;
    private final RateLimit rateLimit;

    /** Precomputed upper-cased category keys, for case-insensitive membership checks. */
    private final Set<String> normalisedCategoryKeys;

    @ConstructorBinding
    public WsaPolicyProperties(Map<String, String> categories,
                               Map<String, Integer> severityScores,
                               Map<String, Integer> actionScores,
                               Scoring scoring,
                               RateLimit rateLimit) {
        this.categories = categories == null ? Map.of() : Map.copyOf(categories);
        this.severityScores = severityScores == null ? Map.of() : Map.copyOf(severityScores);
        this.actionScores = actionScores == null ? Map.of() : Map.copyOf(actionScores);
        this.scoring = scoring == null ? Scoring.defaults() : scoring;
        this.rateLimit = rateLimit == null ? RateLimit.defaults() : rateLimit;
        this.normalisedCategoryKeys = this.categories.keySet().stream()
                .filter(k -> k != null && !k.isBlank())
                .map(WsaPolicyProperties::normalise)
                .collect(Collectors.toUnmodifiableSet());
    }

    /**
     * Convenience constructor for tests and simple wiring that only care about the score
     * maps; {@code scoring} and {@code rateLimit} fall back to their defaults.
     */
    public WsaPolicyProperties(Map<String, String> categories,
                               Map<String, Integer> severityScores,
                               Map<String, Integer> actionScores) {
        this(categories, severityScores, actionScores, Scoring.defaults(), RateLimit.defaults());
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

    /** @return threat-scoring tunables */
    public Scoring getScoring() {
        return scoring;
    }

    /** @return sliding-window rate-limit settings */
    public RateLimit getRateLimit() {
        return rateLimit;
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

    /**
     * Threat-scoring tunables applied during enrichment.
     *
     * @param sensitivePathBonus  points added when the request path is sensitive
     * @param repeatOffenderBonus points added when the client IP is a repeat offender
     * @param maxScore            hard cap on the final threat score
     * @param sensitivePaths      path fragments treated as sensitive (case-insensitive
     *                            "contains" match)
     */
    public record Scoring(
            int sensitivePathBonus,
            int repeatOffenderBonus,
            int maxScore,
            List<String> sensitivePaths
    ) {
        public Scoring {
            sensitivePaths = sensitivePaths == null ? List.of() : List.copyOf(sensitivePaths);
        }

        /** @return sensible defaults matching the reference policy file */
        public static Scoring defaults() {
            return new Scoring(15, 15, 100, List.of("/admin", "/login"));
        }

        /**
         * Tests whether the given path is sensitive (case-insensitive substring match
         * against any configured fragment).
         *
         * @param path the request path
         * @return {@code true} if the path contains a configured sensitive fragment
         */
        public boolean isSensitivePath(String path) {
            if (path == null || path.isBlank()) {
                return false;
            }
            String lower = path.toLowerCase(Locale.ROOT);
            return sensitivePaths.stream()
                    .filter(p -> p != null && !p.isBlank())
                    .anyMatch(p -> lower.contains(p.toLowerCase(Locale.ROOT)));
        }
    }

    /**
     * Sliding-window rate-limit settings.
     *
     * @param window    length of the sliding window
     * @param threshold event count within the window above which an IP is a repeat
     *                  offender (i.e. offender when {@code count > threshold})
     */
    public record RateLimit(Duration window, int threshold) {
        public RateLimit {
            window = window == null ? Duration.ofMinutes(10) : window;
        }

        /** @return sensible defaults: 10-minute window, threshold of 5 */
        public static RateLimit defaults() {
            return new RateLimit(Duration.ofMinutes(10), 5);
        }
    }
}
