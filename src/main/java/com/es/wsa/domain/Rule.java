package com.es.wsa.domain;

/**
 * A security rule that matched a request, as reported inside a {@link SecurityEvent}.
 *
 * <p>Note that {@code category} is intentionally a plain {@link String} rather than an
 * enum: the set of valid attack categories is loaded dynamically from configuration
 * (see {@code AttackCategoryProperties}) and validated at ingestion time, so new
 * categories can be introduced without a code change.
 *
 * @param id       stable identifier of the rule
 * @param name     human-readable rule name
 * @param message  descriptive message emitted when the rule fired, may be {@code null}
 * @param severity how serious a match on this rule is
 * @param category attack category (validated dynamically against configuration)
 * @param action   enforcement action taken when the rule matched
 */
public record Rule(
        String id,
        String name,
        String message,
        Severity severity,
        String category,
        Action action
) {
}
