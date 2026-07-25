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
import java.time.OffsetDateTime;
import java.util.List;

/**
 * Tracks per-client-IP request rates using a Redis sorted-set (ZSET) sliding window.
 *
 * <p>For each IP a ZSET keyed {@code "ip_events:" + clientIp} holds one member per event:
 * the member is the event's unique {@code eventId} and the score is the event's
 * epoch-millisecond timestamp. Using the {@code eventId} as the member makes reprocessing
 * idempotent — a retry of the same event re-adds the same member, so {@code ZADD} updates
 * its score in place instead of double-counting one logical event and inflating the
 * window count.
 *
 * <p><strong>Event time, not processing time.</strong> The window is anchored on the
 * event's own {@code timestamp} (event time), not the server's wall clock. Both the score
 * of the new member and the eviction cutoff ({@code eventTime - window}) are derived from
 * the event timestamp, so late-arriving events or a client backlog are placed correctly on
 * the timeline and do not produce false repeat-offender positives. On every observation the
 * window is advanced and the current count returned atomically via a Lua script, which
 * within one server-side execution:
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
 * count within the window <em>exceeds</em> the threshold. The key TTL is a fixed
 * {@value #KEY_TTL_SECONDS}s (2 hours) — comfortably longer than any window — so idle IP
 * keys expire safely regardless of the configured window length.
 */
@Service
public class IpRateTrackerService {

    private static final Logger log = LoggerFactory.getLogger(IpRateTrackerService.class);

    /** Prefix for per-IP ZSET keys. */
    public static final String KEY_PREFIX = "ip_events:";

    /**
     * Fixed TTL (2 hours) refreshed on every observation so idle IP keys expire safely.
     * Decoupled from the window length: with event-time windows an event may arrive well
     * after its timestamp, so the TTL must outlive plausible lateness rather than track the
     * (potentially short) window.
     */
    static final long KEY_TTL_SECONDS = 7_200L;

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
     * <p>The window is anchored on {@code eventTime} (event time), not the server clock:
     * the new member is scored at {@code eventTime} and the eviction cutoff is
     * {@code eventTime - window}. This keeps late-arriving events and client backlogs from
     * producing false repeat-offender positives.
     *
     * <p>The {@code eventId} is used as the ZSET member so reprocessing is idempotent: a
     * retry carrying the same {@code eventId} updates the existing member's score rather
     * than adding a duplicate, keeping the window count accurate.
     *
     * @param clientIp  the client IP to track; a blank/null IP is treated as not-exceeded
     *                  (nothing to track) and skips Redis
     * @param eventId   the event's unique id, used as the dedup member value; a blank/null
     *                  id is treated as not-exceeded (cannot dedup safely) and skips Redis
     * @param eventTime the event's own timestamp (event time) that anchors the window; a
     *                  null timestamp is treated as not-exceeded and skips Redis
     * @return {@code true} if the IP's event count in the window is greater than the
     * configured threshold (repeat offender)
     */
    public boolean recordAndCheckExceeded(String clientIp, String eventId, OffsetDateTime eventTime) {
        if (clientIp == null || clientIp.isBlank()
                || eventId == null || eventId.isBlank()
                || eventTime == null) {
            return false;
        }

        long eventMillis = eventTime.toInstant().toEpochMilli();
        long windowStart = eventMillis - window.toMillis();

        Long count = redis.execute(
                slidingWindowScript,
                List.of(KEY_PREFIX + clientIp),
                Long.toString(eventMillis),
                Long.toString(windowStart),
                eventId,
                Long.toString(KEY_TTL_SECONDS));

        long observed = count == null ? 0L : count;
        boolean exceeded = observed > threshold;
        if (exceeded) {
            log.debug("IP {} is a repeat offender: {} events in the last {} (threshold {})",
                    clientIp, observed, window, threshold);
        }
        return exceeded;
    }
}
