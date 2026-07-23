package com.es.wsa.datagen;

import com.es.wsa.domain.Action;
import com.es.wsa.domain.GeoLocation;
import com.es.wsa.domain.Rule;
import com.es.wsa.domain.SecurityEvent;
import com.es.wsa.domain.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Random;
import java.util.UUID;

/**
 * Generates realistic {@link SecurityEvent}s for testing and load simulation, driven by an
 * {@link AttackProfile}.
 *
 * <p>This is a plain, dependency-light Java class — not a Spring component. It can be
 * constructed and driven directly (see {@link #main(String[])} for standalone file
 * generation, or the dev-only {@code DevDataGenController} which wires it in-process).
 *
 * <p>Output is split into two kinds of traffic (see {@link AttackProfile#attackWaveRatio()}):
 * <ul>
 *   <li><b>Background</b> — independent one-off events from many different client IPs,
 *       spread uniformly across the profile's {@code timeSpan}. A realistic mix of benign
 *       ({@code MONITOR}/{@code LOW}) and malicious traffic.</li>
 *   <li><b>Attack waves</b> — a single client IP hammering a single path/category with
 *       {@link AttackProfile#waveSize()} events clustered inside
 *       {@link AttackProfile#waveWindow()}. Because {@code waveSize} exceeds the rate-limit
 *       threshold and {@code waveWindow} sits inside the rate-limit window, waves trip the
 *       repeat-offender bonus in the enrichment stage.</li>
 * </ul>
 *
 * <p>The generator emits <em>client-payload</em> fields only — {@code receivedAt},
 * {@code attackType} and {@code threatScore} are left {@code null} because they are stamped
 * by the server (ingestion) and enrichment stages, exactly as a real client would send.
 *
 * <p>Attack categories are supplied at construction (the dev endpoint passes the live
 * {@code WsaPolicyProperties} vocabulary), so every generated event's {@code rule.category}
 * is accepted by {@code SecurityEventValidator}. Randomness flows entirely through a single
 * seeded {@link Random} so a given {@link AttackProfile#seed()} reproduces the same dataset.
 */
public class SecurityEventGenerator {

    private static final Logger log = LoggerFactory.getLogger(SecurityEventGenerator.class);

    /** Categories used when none are supplied (standalone {@link #main} runs). */
    static final List<String> DEFAULT_CATEGORIES = List.of(
            "INJECTION", "XSS", "PROTOCOL_VIOLATION", "DATA_LEAKAGE", "BOT", "DOS", "RATE_LIMIT");

    private static final List<String> HOSTNAMES = List.of(
            "app.example.com", "api.example.com", "shop.example.com",
            "portal.example.com", "admin.example.com");

    /** A benign path is picked for background noise; sensitive ones drive the path bonus. */
    private static final List<String> BENIGN_PATHS = List.of(
            "/", "/home", "/products", "/search", "/cart", "/static/app.js", "/api/v1/orders");
    private static final List<String> SENSITIVE_PATHS = List.of(
            "/admin", "/admin/users", "/login", "/api/v1/login", "/wp-login.php");

    private static final List<String> METHODS = List.of("GET", "POST", "PUT", "DELETE");

    private static final List<String> USER_AGENTS = List.of(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "curl/8.4.0",
            "python-requests/2.31.0",
            "sqlmap/1.8",
            "Googlebot/2.1 (+http://www.google.com/bot.html)");

    /** Country / representative-city pairs for a plausible {@link GeoLocation}. */
    private static final List<GeoLocation> GEOS = List.of(
            new GeoLocation("US", "New York"),
            new GeoLocation("US", "San Francisco"),
            new GeoLocation("GB", "London"),
            new GeoLocation("DE", "Berlin"),
            new GeoLocation("CN", "Shanghai"),
            new GeoLocation("RU", "Moscow"),
            new GeoLocation("BR", "Sao Paulo"),
            new GeoLocation("IN", "Mumbai"));

    private final List<String> categories;
    private final Clock clock;

    /**
     * @param categories the attack-category vocabulary to draw {@code rule.category} from;
     *                   must be non-empty (typically {@code WsaPolicyProperties.categoryKeys()})
     */
    public SecurityEventGenerator(Collection<String> categories) {
        this(categories, Clock.systemDefaultZone());
    }

    /**
     * Constructor allowing a fixed {@link Clock} to be supplied, so that a given seed
     * reproduces byte-for-byte identical timestamps in tests.
     *
     * @param categories the attack-category vocabulary (must be non-empty)
     * @param clock      the clock used for the reference "now"
     */
    public SecurityEventGenerator(Collection<String> categories, Clock clock) {
        if (categories == null || categories.isEmpty()) {
            throw new IllegalArgumentException("categories must be non-empty");
        }
        this.categories = List.copyOf(categories);
        this.clock = clock;
    }

    /**
     * Generates a dataset for the given profile.
     *
     * @param profile generation knobs; if {@code null}, {@link AttackProfile#withDefaults()}
     *                is used
     * @return a shuffled list of {@code profile.totalEvents()} events mixing background
     * traffic and attack waves
     */
    public List<SecurityEvent> generate(AttackProfile profile) {
        AttackProfile p = profile == null ? AttackProfile.withDefaults() : profile;
        Random rng = p.seed() == null ? new Random() : new Random(p.seed());

        int waveTarget = (int) Math.round(p.totalEvents() * p.attackWaveRatio());
        int backgroundCount = p.totalEvents() - waveTarget;

        OffsetDateTime now = OffsetDateTime.now(clock);
        OffsetDateTime start = now.minus(p.timeSpan());
        long spanSeconds = Math.max(1, Duration.between(start, now).getSeconds());

        List<SecurityEvent> events = new ArrayList<>(p.totalEvents());
        for (int i = 0; i < backgroundCount; i++) {
            events.add(backgroundEvent(rng, p, start, spanSeconds));
        }
        int wavesEmitted = appendWaves(events, rng, p, start, spanSeconds, waveTarget);

        // Order the whole dataset by event time so it is fed (and thus ingested) in
        // chronological order. This interleaves waves with background traffic — like a real
        // event stream — and, crucially, makes ingestion order match event-time order: the
        // per-IP rate-limit sliding window then observes a wave's events in the same order
        // their timestamps occur, so the repeat-offender flag flips true exactly when the
        // running count crosses the threshold (rather than at a random point set by shuffle).
        events.sort(Comparator.comparing(SecurityEvent::timestamp));

        log.info("Generated {} events ({} background, {} across {} attack wave(s))",
                events.size(), backgroundCount, waveTarget, wavesEmitted);
        return events;
    }

    /** A single independent event from a random client, path and category. */
    private SecurityEvent backgroundEvent(Random rng, AttackProfile p,
                                          OffsetDateTime start, long spanSeconds) {
        OffsetDateTime ts = start.plusSeconds(nextLong(rng, spanSeconds));
        String clientIp = randomIp(rng);
        // ~35% of background traffic targets a sensitive path; the rest is benign noise.
        String path = rng.nextInt(100) < 35 ? pick(rng, SENSITIVE_PATHS) : pick(rng, BENIGN_PATHS);
        String category = pick(rng, categories);
        return buildEvent(rng, p, ts, clientIp, path, category);
    }

    /**
     * Appends attack waves until at least {@code waveTarget} wave events have been produced.
     * Each wave is one IP + one path/category, {@code waveSize} events clustered in
     * {@code waveWindow}.
     *
     * @return the number of waves emitted
     */
    private int appendWaves(List<SecurityEvent> events, Random rng, AttackProfile p,
                            OffsetDateTime start, long spanSeconds, int waveTarget) {
        int emitted = 0;
        int waves = 0;
        long windowSeconds = Math.max(1, p.waveWindow().getSeconds());
        while (emitted < waveTarget) {
            String attackerIp = randomIp(rng);
            String path = pick(rng, SENSITIVE_PATHS);
            String category = pick(rng, categories);
            // Anchor the wave so its whole window fits inside the time span.
            long anchorMax = Math.max(1, spanSeconds - windowSeconds);
            OffsetDateTime waveStart = start.plusSeconds(nextLong(rng, anchorMax));

            int remaining = waveTarget - emitted;
            int size = Math.min(p.waveSize(), remaining);
            for (int i = 0; i < size; i++) {
                OffsetDateTime ts = waveStart.plusSeconds(nextLong(rng, windowSeconds));
                events.add(buildEvent(rng, p, ts, attackerIp, path, category));
            }
            emitted += size;
            waves++;
        }
        return waves;
    }

    /** Assembles a client-payload event; enrichment/ingestion fields are left null. */
    private SecurityEvent buildEvent(Random rng, AttackProfile p, OffsetDateTime timestamp,
                                     String clientIp, String path, String category) {
        Severity severity = pick(rng, Severity.values());
        Action action = pick(rng, Action.values());
        Rule rule = new Rule(
                "rule-" + (1000 + rng.nextInt(9000)),
                ruleName(category),
                category + " signature matched",
                severity,
                category,
                action);

        String method = pick(rng, METHODS);
        int statusCode = statusFor(action);
        long requestSize = 200 + nextLong(rng, 4_000);
        long responseSize = 200 + nextLong(rng, 20_000);

        return new SecurityEvent(
                "evt-" + randomId(rng),
                timestamp,
                pick(rng, p.configIds()),
                "policy-" + (100 + rng.nextInt(900)),
                clientIp,
                pick(rng, HOSTNAMES),
                path,
                method,
                statusCode,
                pick(rng, USER_AGENTS),
                requestSize,
                responseSize,
                null,   // receivedAt — stamped by the server at ingestion
                rule,
                pick(rng, GEOS),
                null,   // attackType — set during enrichment
                null,   // threatScore — set during enrichment
                false); // repeatOffender — set during enrichment
    }

    private static String ruleName(String category) {
        return switch (category) {
            case "INJECTION" -> "SQL/Command Injection";
            case "XSS" -> "Cross-Site Scripting";
            case "PROTOCOL_VIOLATION" -> "Protocol Violation";
            case "DATA_LEAKAGE" -> "Data Leakage";
            case "BOT" -> "Bot Activity";
            case "DOS" -> "Denial of Service";
            case "RATE_LIMIT" -> "Rate Limit Exceeded";
            default -> category;
        };
    }

    /** A blocked action tends to yield 403; alert/monitor pass through with varied codes. */
    private int statusFor(Action action) {
        return action == Action.DENY ? 403 : (action == Action.ALERT ? 401 : 200);
    }

    /** A random dotted-quad client IP, drawn from the seeded RNG. */
    private static String randomIp(Random rng) {
        return (1 + rng.nextInt(223)) + "." + rng.nextInt(256) + "."
                + rng.nextInt(256) + "." + (1 + rng.nextInt(254));
    }

    /** A reproducible pseudo-random id (RNG-derived, so it honours the seed). */
    private static String randomId(Random rng) {
        long high = rng.nextLong();
        long low = rng.nextLong();
        return new UUID(high, low).toString();
    }

    private static <T> T pick(Random rng, List<T> options) {
        return options.get(rng.nextInt(options.size()));
    }

    private static <T> T pick(Random rng, T[] options) {
        return options[rng.nextInt(options.length)];
    }

    /** Uniform long in {@code [0, boundExclusive)}. */
    private static long nextLong(Random rng, long boundExclusive) {
        return boundExclusive <= 0 ? 0 : Math.floorMod(rng.nextLong(), boundExclusive);
    }

    /**
     * Standalone entry point: generate a dataset and write it to disk in both JSON and CSV.
     *
     * <p>Usage: {@code SecurityEventGenerator [outputDir] [totalEvents] [seed]}. All
     * arguments are optional; defaults are {@code ./data}, the profile default count, and a
     * non-deterministic seed. Writes {@code events.json} and {@code events.csv}.
     *
     * @param args {@code [outputDir] [totalEvents] [seed]}
     */
    public static void main(String[] args) {
        Path outputDir = Path.of(args.length > 0 ? args[0] : "./data");
        AttackProfile profile = AttackProfile.withDefaults();
        if (args.length > 1) {
            profile = profile.withTotalEvents(Integer.parseInt(args[1]));
        }
        if (args.length > 2) {
            long seed = Long.parseLong(args[2]);
            profile = new AttackProfile(profile.totalEvents(), profile.attackWaveRatio(),
                    profile.waveSize(), profile.waveWindow(), profile.configIds(),
                    profile.timeSpan(), seed);
        }

        List<SecurityEvent> events = new SecurityEventGenerator(DEFAULT_CATEGORIES).generate(profile);
        EventFileWriter writer = new EventFileWriter();
        writer.write(events, outputDir.resolve("events.json"), EventFileFormat.JSON);
        writer.write(events, outputDir.resolve("events.csv"), EventFileFormat.CSV);
        log.info("Wrote {} events to {}", events.size(), outputDir.toAbsolutePath());
    }
}

