package com.es.wsa.stats;

import java.time.OffsetDateTime;

/**
 * Validated, parsed query parameters for a statistics summary request. All fields are
 * optional: a {@code null} means "no constraint on this dimension".
 *
 * @param configId when set, restrict aggregation to this configuration; {@code null}
 *                 aggregates across all configurations
 * @param from     inclusive lower bound on the event {@code timestamp}; {@code null} is unbounded
 * @param to       inclusive upper bound on the event {@code timestamp}; {@code null} is unbounded
 */
public record StatsQuery(Long configId, OffsetDateTime from, OffsetDateTime to) {
}
