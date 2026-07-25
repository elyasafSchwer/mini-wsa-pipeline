package com.es.wsa.standalone;

import com.es.wsa.config.WsaPolicyProperties;
import com.es.wsa.ratelimit.IpRateTrackerService;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory per-IP sliding-window rate tracker for the {@code standalone} profile.
 *
 * <p>Extends {@link IpRateTrackerService} (which has no interface) so it can satisfy the
 * concrete-type injection in {@code EnrichmentServiceImpl} without modifying that class.
 * {@code super(null, policies)} is safe: the parent constructor never dereferences the Redis
 * template — it only reads {@code policies.getRateLimit()} and builds a Lua script from the
 * classpath — and this class overrides the sole method that would use Redis.
 *
 * <p>The algorithm mirrors the Lua {@code sliding_window.lua} script: keep, per IP, a map of
 * {@code eventId → eventEpochMillis}; on each observation upsert by {@code eventId}
 * (idempotent, like {@code ZADD} keyed on the member), evict entries older than
 * {@code eventTime - window}, and flag a repeat offender when the surviving count strictly
 * exceeds the threshold. Anchoring on event time (not wall-clock) matches the production
 * behaviour.
 */
@Component
@Primary
@Profile("standalone")
public class InMemoryIpRateTracker extends IpRateTrackerService {

    private final long windowMillis;
    private final int threshold;

    /** IP → (eventId → event epoch millis). */
    private final Map<String, Map<String, Long>> perIp = new ConcurrentHashMap<>();

    public InMemoryIpRateTracker(WsaPolicyProperties policies) {
        super(null, policies);
        this.windowMillis = policies.getRateLimit().window().toMillis();
        this.threshold = policies.getRateLimit().threshold();
    }

    @Override
    public boolean recordAndCheckExceeded(String clientIp, String eventId, OffsetDateTime eventTime) {
        if (clientIp == null || clientIp.isBlank()
                || eventId == null || eventId.isBlank()
                || eventTime == null) {
            return false;
        }

        long eventMillis = eventTime.toInstant().toEpochMilli();
        long cutoff = eventMillis - windowMillis;

        Map<String, Long> events = perIp.computeIfAbsent(clientIp, k -> new ConcurrentHashMap<>());
        long count;
        synchronized (events) {
            events.put(eventId, eventMillis);               // idempotent upsert (ZADD by member)
            events.values().removeIf(ts -> ts < cutoff);    // evict outside window (ZREMRANGEBYSCORE)
            count = events.size();                          // ZCARD
        }
        return count > threshold;                            // offender when strictly greater
    }

    /**
     * @return a snapshot of the client IPs currently tracked (used by the in-memory
     * {@code StringRedisTemplate} to answer {@code keys("ip_events:*")} for {@code /api/dev/clear})
     */
    public Set<String> ipKeys() {
        return new HashSet<>(perIp.keySet());
    }

    /**
     * Removes tracking state for the given client IPs.
     *
     * @param clientIps the IPs to clear
     */
    public void clearKeys(Collection<String> clientIps) {
        clientIps.forEach(perIp::remove);
    }
}
