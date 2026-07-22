package com.es.wsa.validation;

import java.util.List;

/**
 * Outcome of validating a single {@link com.es.wsa.domain.SecurityEvent}.
 *
 * <p>Collects <em>all</em> problems found rather than failing on the first, so callers
 * (e.g. the ingestion API) can report everything wrong with a payload at once.
 *
 * @param valid  {@code true} when {@link #errors} is empty
 * @param errors human-readable validation error messages (empty when valid)
 */
public record ValidationResult(boolean valid, List<String> errors) {

    public ValidationResult {
        errors = errors == null ? List.of() : List.copyOf(errors);
    }

    /** @return a successful result with no errors */
    public static ValidationResult ok() {
        return new ValidationResult(true, List.of());
    }

    /**
     * Builds a result from the given error messages. The result is valid iff the list
     * is empty.
     *
     * @param errors the collected error messages
     * @return a {@link ValidationResult} reflecting the given errors
     */
    public static ValidationResult of(List<String> errors) {
        return new ValidationResult(errors == null || errors.isEmpty(), errors);
    }
}
