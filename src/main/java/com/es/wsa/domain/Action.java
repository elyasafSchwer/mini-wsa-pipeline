package com.es.wsa.domain;

/**
 * The enforcement action the WAF took when a {@link Rule} matched.
 *
 * <ul>
 *   <li>{@code DENY} — the request was blocked.</li>
 *   <li>{@code ALERT} — the request was allowed but an alert was raised.</li>
 *   <li>{@code MONITOR} — the request was allowed and only logged.</li>
 * </ul>
 */
public enum Action {
    DENY,
    ALERT,
    MONITOR
}
