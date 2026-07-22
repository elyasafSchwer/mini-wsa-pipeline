package com.es.wsa.ratelimit;

import com.es.wsa.config.WsaPolicyProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.scripting.support.ResourceScriptSource;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.List;

/**
 * Tracks per-client-IP request rates using a Redis sorted-set (ZSET) sliding window.
 *
 * <p>For each IP a ZSET keyed {@code "ip_events:" + clientIp} holds one member per event:
 * the member is the event's unique {@code eventId} and the score is the event's
 * epoch-millisecond timestamp. Using the {@code eventId} as the member makes reprocessing
 * idempotent — a retry of the same event re-adds the same member, so {@code ZADD} updates
 * its score in place instead of double-counting one logical event and inflating the
 * window count. On every observation the window is advanced and the current count returned
 * atomically via a Lua script, which within one server-side execution:
 * <ol>
 *   <li>evicts entries older than the window ({@code ZREMRANGEBYSCORE}),</li>
 *   <li>adds the current event ({@code ZADD}),</li>
 *   <li>refreshes the key TTL ({@code EXPIRE}) so idle IPs self-clean, and</li>
 *   <li>returns the remaining count ({@code ZCARD}).</li>
 * </ol>
 * Using a single script guarantees atomicity and one network round-trip per IP, avoiding
 * the race a multi-command sequence would have under concurrency.
 *
 * <p>The window length and the repeat-offender threshold are configuration-driven
 * ({@code wsa.policies.rate-limit}); an IP is considered a repeat offender when its event
 * count within the window <em>exceeds</em> the threshold.
 */
@Service
public class IpRateTrackerService {

    private static final Logger log = LoggerFactory.getLogger(IpRateTrackerService.class);

    /** Prefix for per-IP ZSET keys. */
    static final String KEY_PREFIX = "ip_events:";

    private final StringRedisTemplate redis;
    private final RedisScript<Long> slidingWindowScript;
    private final Duration window;
    private final int threshold;

    public IpRateTrackerService(StringRedisTemplate redis, WsaPolicyProperties policies) {
        this.redis = redis;
        this.window = policies.getRateLimit().window();
        this.threshold = policies.getRateLimit().threshold();

        DefaultRedisScript<Long> script = new DefaultRedisScript<>();
        script.setScriptSource(new ResourceScriptSource(new ClassPathResource("redis/sliding_window.lua")));
        script.setResultType(Long.class);
        this.slidingWindowScript = script;
    }

    /**
     * Records the given event for its client IP and reports whether the IP has exceeded
     * the configured threshold within the sliding window.
     *
     * <p>The {@code eventId} is used as the ZSET member so reprocessing is idempotent: a
     * retry carrying the same {@code eventId} updates the existing member's score rather
     * than adding a duplicate, keeping the window count accurate.
     *
     * @param clientIp the client IP to track; a blank/null IP is treated as not-exceeded
     *                 (nothing to track) and skips Redis
     * @param eventId  the event's unique id, used as the dedup member value; a blank/null
     *                 id is treated as not-exceeded (cannot dedup safely) and skips Redis
     * @return {@code true} if the IP's event count in the window is greater than the
     * configured threshold (repeat offender)
     */
    public boolean recordAndCheckExceeded(String clientIp, String eventId) {
        if (clientIp == null || clientIp.isBlank() || eventId == null || eventId.isBlank()) {
            return false;
        }

        long now = System.currentTimeMillis();
        long windowStart = now - window.toMillis();
        long ttlSeconds = window.toSeconds();

        Long count = redis.execute(
                slidingWindowScript,
                List.of(KEY_PREFIX + clientIp),
                Long.toString(now),
                Long.toString(windowStart),
                eventId,
                Long.toString(ttlSeconds));

        long observed = count == null ? 0L : count;
        boolean exceeded = observed > threshold;
        if (exceeded) {
            log.debug("IP {} is a repeat offender: {} events in the last {} (threshold {})",
                    clientIp, observed, window, threshold);
        }
        return exceeded;
    }
}
