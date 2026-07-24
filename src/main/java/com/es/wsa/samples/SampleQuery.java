package com.es.wsa.samples;

import java.time.OffsetDateTime;

/**
 * Validated, parsed filter + pagination parameters for a samples request. All filter
 * fields are optional ({@code null} means "no constraint on this dimension"); the paging
 * fields always carry effective values (defaults/clamping applied by the controller).
 *
 * @param configId when set, restrict to this configuration
 * @param from     inclusive lower bound on the event {@code timestamp}; {@code null} unbounded
 * @param to       inclusive upper bound on the event {@code timestamp}; {@code null} unbounded
 * @param category when set, restrict to this attack category ({@code rule.category})
 * @param action   when set, restrict to this enforcement action ({@code rule.action})
 * @param limit    maximum number of records to return (page size)
 * @param offset   number of records to skip (for pagination)
 */
public record SampleQuery(
        Long configId,
        OffsetDateTime from,
        OffsetDateTime to,
        String category,
        String action,
        int limit,
        int offset
) {
}
