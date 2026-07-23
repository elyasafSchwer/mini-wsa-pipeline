package com.es.wsa.datagen;

import java.time.Duration;
import java.util.List;

/**
 * Tunable knobs for {@link SecurityEventGenerator}. All fields are optional in the sense
 * that {@link #withDefaults()} supplies sensible values; the REST layer overlays only the
 * fields a caller specifies.
 *
 * @param totalEvents     total number of events to generate (background + waves)
 * @param attackWaveRatio fraction of {@code totalEvents} that belong to attack waves,
 *                        in {@code [0.0, 1.0]}; the remainder is background traffic
 * @param waveSize        number of events per attack wave (one IP hitting one path,
 *                        clustered in time). Should exceed the rate-limit threshold so
 *                        waves trip the repeat-offender bonus
 * @param waveWindow      time span over which a single wave's events are clustered; kept
 *                        short (well inside the rate-limit window) so the wave counts as a
 *                        burst under the event-time sliding window
 * @param configIds       the pool of configuration ids events are randomly assigned to
 * @param timeSpan        events' {@code timestamp}s are spread across {@code [now - timeSpan, now]}
 * @param seed            RNG seed for reproducible datasets; {@code null} means non-deterministic
 */
public record AttackProfile(
        int totalEvents,
        double attackWaveRatio,
        int waveSize,
        Duration waveWindow,
        List<Long> configIds,
        Duration timeSpan,
        Long seed
) {

    public AttackProfile {
        if (totalEvents < 0) {
            throw new IllegalArgumentException("totalEvents must not be negative");
        }
        if (attackWaveRatio < 0.0 || attackWaveRatio > 1.0) {
            throw new IllegalArgumentException("attackWaveRatio must be in [0.0, 1.0]");
        }
        if (waveSize < 1) {
            throw new IllegalArgumentException("waveSize must be at least 1");
        }
        waveWindow = waveWindow == null ? Duration.ofMinutes(2) : waveWindow;
        timeSpan = timeSpan == null ? Duration.ofDays(1) : timeSpan;
        configIds = (configIds == null || configIds.isEmpty())
                ? List.of(14227L, 22841L, 30199L)
                : List.copyOf(configIds);
    }

    /** @return a profile generating 10,000 events with ~30% attack-wave traffic. */
    public static AttackProfile withDefaults() {
        return new AttackProfile(
                10_000,
                0.30,
                25,
                Duration.ofMinutes(2),
                List.of(14227L, 22841L, 30199L),
                Duration.ofDays(1),
                null);
    }

    /**
     * Returns a copy with {@code totalEvents} overridden (used by the REST layer when a
     * caller specifies only a count).
     */
    public AttackProfile withTotalEvents(int newTotal) {
        return new AttackProfile(newTotal, attackWaveRatio, waveSize, waveWindow,
                configIds, timeSpan, seed);
    }
}
