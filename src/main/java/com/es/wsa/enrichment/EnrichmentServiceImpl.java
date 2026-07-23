package com.es.wsa.enrichment;

import com.es.wsa.config.WsaPolicyProperties;
import com.es.wsa.domain.Action;
import com.es.wsa.domain.Rule;
import com.es.wsa.domain.SecurityEvent;
import com.es.wsa.domain.Severity;
import com.es.wsa.ratelimit.IpRateTrackerService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Default {@link EventProcessor} that maps the rule category to an {@code attackType} and
 * computes a bounded {@code threatScore}.
 *
 * <p>The threat score is assembled from configuration-driven building blocks
 * ({@code wsa.policies}) so the scoring model is tunable without code changes:
 * <ol>
 *   <li>base = severity score + action score (from the score maps),</li>
 *   <li>+ sensitive-path bonus when the path targets e.g. {@code /admin} or {@code /login},</li>
 *   <li>+ repeat-offender bonus when {@link IpRateTrackerService} flags the client IP,</li>
 *   <li>clamped to {@code [0, maxScore]} (default cap 100).</li>
 * </ol>
 *
 * <p>The {@code attackType} is the configured display name for the rule's category when
 * known, falling back to the raw category value otherwise, so downstream consumers always
 * get a meaningful label.
 */
@Service
public class EnrichmentServiceImpl implements EventProcessor {

    private static final Logger log = LoggerFactory.getLogger(EnrichmentServiceImpl.class);

    private final WsaPolicyProperties policies;
    private final IpRateTrackerService rateTracker;

    public EnrichmentServiceImpl(WsaPolicyProperties policies, IpRateTrackerService rateTracker) {
        this.policies = policies;
        this.rateTracker = rateTracker;
    }

    @Override
    public SecurityEvent process(SecurityEvent event) {
        String attackType = resolveAttackType(event.rule());

        // Capture the repeat-offender decision once so it drives both the score bonus and
        // the persisted flag (the rate tracker must only be consulted a single time per
        // event — it mutates the sliding-window count).
        boolean repeatOffender = rateTracker.recordAndCheckExceeded(
                event.clientIp(), event.eventId(), event.timestamp());
        int threatScore = computeThreatScore(event, repeatOffender);

        log.debug("Enriched event {}: attackType={}, threatScore={}, repeatOffender={}",
                event.eventId(), attackType, threatScore, repeatOffender);

        return event
                .withAttackType(attackType)
                .withThreatScore(threatScore)
                .withRepeatOffender(repeatOffender);
    }

    /**
     * Maps {@code rule.category} to a human-readable attack type: the configured display
     * name when the category is known, otherwise the raw category value (or {@code null}
     * when no rule/category is present).
     */
    private String resolveAttackType(Rule rule) {
        if (rule == null || rule.category() == null || rule.category().isBlank()) {
            return null;
        }
        String category = rule.category();
        String displayName = policies.displayNameFor(category);
        return displayName != null ? displayName : category;
    }

    /**
     * Computes the bounded threat score from severity/action base scores plus the
     * sensitive-path and repeat-offender bonuses.
     *
     * @param repeatOffender whether the client IP was flagged as a repeat offender (decided
     *                       by the caller so the rate tracker is consulted exactly once)
     */
    private int computeThreatScore(SecurityEvent event, boolean repeatOffender) {
        WsaPolicyProperties.Scoring scoring = policies.getScoring();

        int score = baseScore(event.rule());

        if (scoring.isSensitivePath(event.path())) {
            score += scoring.sensitivePathBonus();
        }

        if (repeatOffender) {
            score += scoring.repeatOffenderBonus();
        }

        return clamp(score, scoring.maxScore());
    }

    /** base = severity score + action score, both looked up from configuration. */
    private int baseScore(Rule rule) {
        if (rule == null) {
            return 0;
        }
        Severity severity = rule.severity();
        Action action = rule.action();
        int severityScore = severity == null ? 0 : policies.severityScore(severity.name());
        int actionScore = action == null ? 0 : policies.actionScore(action.name());
        return severityScore + actionScore;
    }

    private static int clamp(int score, int max) {
        if (score < 0) {
            return 0;
        }
        return Math.min(score, max);
    }
}
