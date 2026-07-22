package com.es.wsa.domain;

/**
 * Geographic origin of the client that generated a {@link SecurityEvent}.
 *
 * @param country resolved country (e.g. ISO country name or code)
 * @param city    resolved city, may be {@code null} when unknown
 */
public record GeoLocation(
        String country,
        String city
) {
}
