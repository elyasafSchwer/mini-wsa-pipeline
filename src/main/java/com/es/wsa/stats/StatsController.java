package com.es.wsa.stats;

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

/**
 * Read-side statistics API for the stored security events.
 *
 * <p>Exposes {@code GET /v1/stats/summary}, returning a {@link StatsSummaryResponse}
 * aggregated by Elasticsearch. All query parameters are optional:
 * <ul>
 *   <li>{@code configId} — restrict to one configuration; omitted aggregates across all;</li>
 *   <li>{@code from}/{@code to} — inclusive ISO-8601 bounds on the event timestamp.</li>
 * </ul>
 *
 * <p>Following {@code IngestionController}'s convention, validation is explicit and bad
 * input yields a {@code 400} with a clear message rather than a {@code 500}.
 */
@RestController
@RequestMapping("/v1/stats")
public class StatsController {

    private static final Logger log = LoggerFactory.getLogger(StatsController.class);

    private final StatsService statsService;

    public StatsController(StatsService statsService) {
        this.statsService = statsService;
    }

    /**
     * Returns aggregated statistics for the given configuration and time range.
     *
     * @param configId optional configuration filter; omitted aggregates across all configs
     * @param from     optional inclusive lower bound (ISO-8601 offset datetime)
     * @param to       optional inclusive upper bound (ISO-8601 offset datetime)
     * @return {@code 200} with the summary, or {@code 400} if the range is malformed or inverted
     */
    @GetMapping("/summary")
    public StatsSummaryResponse summary(
            @RequestParam(required = false) Long configId,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to) {

        OffsetDateTime fromTs = parse("from", from);
        OffsetDateTime toTs = parse("to", to);

        if (fromTs != null && toTs != null && fromTs.isAfter(toTs)) {
            throw new InvalidStatsQueryException("'from' must not be after 'to'");
        }

        StatsSummaryResponse response = statsService.summarize(new StatsQuery(configId, fromTs, toTs));
        log.debug("stats/summary configId={} from={} to={} -> totalEvents={}",
                configId, from, to, response.totalEvents());
        return response;
    }

    /** Parses an optional ISO-8601 offset datetime, mapping bad input to a 400. */
    private static OffsetDateTime parse(String param, String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return OffsetDateTime.parse(value);
        } catch (DateTimeParseException ex) {
            throw new InvalidStatsQueryException(
                    "'" + param + "' is not a valid ISO-8601 offset datetime: " + value);
        }
    }

    @ExceptionHandler(InvalidStatsQueryException.class)
    public ResponseEntity<StatsErrorResponse> handleInvalidQuery(InvalidStatsQueryException ex) {
        return ResponseEntity.badRequest().body(new StatsErrorResponse(ex.getMessage()));
    }

    /** Signals a malformed statistics query; translated to a {@code 400} by the handler. */
    static class InvalidStatsQueryException extends RuntimeException {
        InvalidStatsQueryException(String message) {
            super(message);
        }
    }

    /**
     * Error body for a rejected statistics request.
     *
     * @param message a short description of what was wrong with the request
     */
    public record StatsErrorResponse(String message) {
    }
}
