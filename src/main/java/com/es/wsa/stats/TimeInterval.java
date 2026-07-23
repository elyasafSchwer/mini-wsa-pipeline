package com.es.wsa.stats;

import java.util.Locale;

/**
 * The bucket granularities supported by {@code GET /v1/stats/timeseries}.
 *
 * <p>Each constant maps a wire token ({@code "1m"}, {@code "5m"}, {@code "1h"}) to the
 * Elasticsearch {@code fixed_interval} string used by the {@code date_histogram}
 * aggregation. Fixed intervals (rather than calendar intervals) are used so buckets are
 * uniform, evenly spaced steps — the natural x-axis for a line chart.
 */
public enum TimeInterval {

    M1("1m"),
    M5("5m"),
    H1("1h");

    private final String token;

    TimeInterval(String token) {
        this.token = token;
    }

    /** @return the wire/Elasticsearch interval token (e.g. {@code "5m"}). */
    public String token() {
        return token;
    }

    /** @return the Elasticsearch {@code fixed_interval} value (same as {@link #token()}). */
    public String esInterval() {
        return token;
    }

    /**
     * Resolves a wire token to an interval, case-insensitively.
     *
     * @param value the token, e.g. {@code "1m"}, {@code "5M"}, {@code "1h"}
     * @return the matching interval
     * @throws IllegalArgumentException if the token is not one of {@code 1m}, {@code 5m}, {@code 1h}
     */
    public static TimeInterval fromToken(String value) {
        if (value != null) {
            String normalised = value.trim().toLowerCase(Locale.ROOT);
            for (TimeInterval interval : values()) {
                if (interval.token.equals(normalised)) {
                    return interval;
                }
            }
        }
        throw new IllegalArgumentException(
                "interval must be one of 1m, 5m, 1h (got: " + value + ")");
    }
}
