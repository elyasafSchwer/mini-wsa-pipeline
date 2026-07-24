package com.es.wsa.samples;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.Locale;

/**
 * Read-side API returning individual enriched event records (as opposed to the aggregate
 * {@code /v1/stats} views).
 *
 * <p>Exposes {@code GET /v1/events/samples}. All filter parameters are optional
 * ({@code configId}, {@code from}, {@code to}, {@code category}, {@code action}); results
 * are sorted by event {@code timestamp} descending (newest first) and paginated via
 * {@code limit} (default {@value #DEFAULT_LIMIT}, max {@value #MAX_LIMIT}) and
 * {@code offset} (default 0). The response carries the total match count for pagination.
 *
 * <p>Following {@code IngestionController}/{@code StatsController} convention, validation is
 * explicit and bad input yields a {@code 400} with a clear message rather than a {@code 500}.
 */
@RestController
@RequestMapping("/v1/events")
public class SamplesController {

    private static final Logger log = LoggerFactory.getLogger(SamplesController.class);

    static final int DEFAULT_LIMIT = 20;
    static final int MAX_LIMIT = 100;

    private final SamplesService samplesService;

    public SamplesController(SamplesService samplesService) {
        this.samplesService = samplesService;
    }

    /**
     * Returns a page of enriched events matching the filters, newest first.
     *
     * @param configId optional configuration filter
     * @param from     optional inclusive lower bound (ISO-8601 offset datetime)
     * @param to       optional inclusive upper bound (ISO-8601 offset datetime)
     * @param category optional attack-category filter ({@code rule.category})
     * @param action   optional enforcement-action filter ({@code rule.action})
     * @param limit    page size, default {@value #DEFAULT_LIMIT}, clamped to [1, {@value #MAX_LIMIT}]
     * @param offset   records to skip, default 0, must be {@code >= 0}
     * @return {@code 200} with the page + total, or {@code 400} on invalid input
     */
    @GetMapping("/samples")
    public SampleResponse samples(
            @RequestParam(required = false) Long configId,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String action,
            @RequestParam(required = false, defaultValue = "20") int limit,
            @RequestParam(required = false, defaultValue = "0") int offset) {

        OffsetDateTime fromTs = parse("from", from);
        OffsetDateTime toTs = parse("to", to);

        if (fromTs != null && toTs != null && fromTs.isAfter(toTs)) {
            throw new InvalidSampleQueryException("'from' must not be after 'to'");
        }
        if (offset < 0) {
            throw new InvalidSampleQueryException("'offset' must not be negative");
        }
        if (limit < 1) {
            throw new InvalidSampleQueryException("'limit' must be at least 1");
        }

        int effectiveLimit = Math.min(limit, MAX_LIMIT);

        SampleQuery query = new SampleQuery(
                configId, fromTs, toTs,
                normalise(category), normalise(action),
                effectiveLimit, offset);

        SampleResponse response = samplesService.findSamples(query);
        log.debug("events/samples configId={} category={} action={} limit={} offset={} -> total={}, returned={}",
                configId, category, action, effectiveLimit, offset, response.total(), response.items().size());
        return response;
    }

    /**
     * Uppercases/​trims a category or action token so filters match the stored keyword
     * values (which are the enum {@code name()} / configured category keys, upper case).
     * Blank/absent stays {@code null} (no filter).
     */
    private static String normalise(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim().toUpperCase(Locale.ROOT);
    }

    /** Parses an optional ISO-8601 offset datetime, mapping bad input to a 400. */
    private static OffsetDateTime parse(String param, String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return OffsetDateTime.parse(value);
        } catch (DateTimeParseException ex) {
            throw new InvalidSampleQueryException(
                    "'" + param + "' is not a valid ISO-8601 offset datetime: " + value);
        }
    }

    @ExceptionHandler(InvalidSampleQueryException.class)
    public ResponseEntity<SampleErrorResponse> handleInvalidQuery(InvalidSampleQueryException ex) {
        return ResponseEntity.badRequest().body(new SampleErrorResponse(ex.getMessage()));
    }

    /** Signals a malformed samples query; translated to a {@code 400} by the handler. */
    static class InvalidSampleQueryException extends RuntimeException {
        InvalidSampleQueryException(String message) {
            super(message);
        }
    }

    /**
     * Error body for a rejected samples request.
     *
     * @param message a short description of what was wrong with the request
     */
    public record SampleErrorResponse(String message) {
    }
}
