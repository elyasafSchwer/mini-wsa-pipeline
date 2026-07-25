package com.es.wsa.standalone;

import com.es.wsa.ratelimit.IpRateTrackerService;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * A {@link StringRedisTemplate} stand-in for the {@code standalone} profile, backed by the
 * {@link InMemoryIpRateTracker} instead of a real Redis connection.
 *
 * <p>{@code DevDataGenController#clear()} is the only code that calls Redis directly, and only
 * via {@link #keys(String)} (with the pattern {@code "ip_events:*"}) and
 * {@link #delete(Collection)}. Overriding just those two methods lets the untouched controller
 * clear the in-memory rate-tracker state. No connection factory is configured — every path
 * that would touch a socket is overridden — so this template never opens a connection.
 */
public class InMemoryStringRedisTemplate extends StringRedisTemplate {

    private final InMemoryIpRateTracker tracker;

    public InMemoryStringRedisTemplate(InMemoryIpRateTracker tracker) {
        super();
        this.tracker = tracker;
    }

    /**
     * No-op override. The base {@code RedisTemplate.afterPropertiesSet()} insists on a
     * {@link org.springframework.data.redis.connection.RedisConnectionFactory}; this stand-in
     * has none and never opens a connection, so initialization must not require one.
     */
    @Override
    public void afterPropertiesSet() {
        // intentionally empty — no connection factory, no serializers to initialise
    }

    @Override
    public Set<String> keys(String pattern) {
        // The only pattern used by the app is IpRateTrackerService.KEY_PREFIX + "*".
        return tracker.ipKeys().stream()
                .map(ip -> IpRateTrackerService.KEY_PREFIX + ip)
                .collect(Collectors.toSet());
    }

    @Override
    public Long delete(Collection<String> keys) {
        List<String> ips = keys.stream()
                .filter(k -> k.startsWith(IpRateTrackerService.KEY_PREFIX))
                .map(k -> k.substring(IpRateTrackerService.KEY_PREFIX.length()))
                .toList();
        tracker.clearKeys(ips);
        return (long) ips.size();
    }
}
