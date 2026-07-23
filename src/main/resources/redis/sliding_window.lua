-- Atomic sliding-window rate check for a single client IP.
--
-- The window is anchored on EVENT TIME (the event's own timestamp), not the server's
-- processing time, so late-arriving events and client backlogs are placed correctly on
-- the timeline and do not cause false repeat-offender positives.
--
-- KEYS[1] = the ZSET key (e.g. "ip_events:1.2.3.4")
-- ARGV[1] = event time in milliseconds (the event's own timestamp; score for the new member)
-- ARGV[2] = event time minus window size, in ms (entries with score < cutoff are evicted)
-- ARGV[3] = the event's unique id, used as the member value. Using the event id
--           (rather than a fresh random value) makes reprocessing idempotent: a retry
--           of the same event re-adds the same member, so ZADD updates its score
--           instead of inflating the window count with a duplicate.
-- ARGV[4] = key TTL in seconds
--
-- Steps (all atomic within this script):
--   1. Drop entries older than the window.
--   2. Add the current event.
--   3. Refresh the key TTL so idle IPs expire.
--   4. Return the number of events now in the window.
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', '(' .. ARGV[2])
redis.call('ZADD', KEYS[1], ARGV[1], ARGV[3])
redis.call('EXPIRE', KEYS[1], ARGV[4])
return redis.call('ZCARD', KEYS[1])
