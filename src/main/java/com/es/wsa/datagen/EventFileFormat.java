package com.es.wsa.datagen;

import java.nio.file.Path;
import java.util.Locale;

/**
 * The two on-disk formats the data generator produces and the feeder can read.
 *
 * <ul>
 *   <li>{@link #JSON} — the original nested {@code SecurityEvent} structure (an array of
 *       event objects), identical to the ingestion payload.</li>
 *   <li>{@link #CSV} — a flat table where nested {@code rule.*} / {@code geoLocation.*}
 *       fields are flattened into dotted top-level columns (see {@link EventCsvMapper}).</li>
 * </ul>
 */
public enum EventFileFormat {

    JSON(".json"),
    CSV(".csv");

    private final String extension;

    EventFileFormat(String extension) {
        this.extension = extension;
    }

    /** @return the canonical file extension (including the leading dot). */
    public String extension() {
        return extension;
    }

    /**
     * Detects the format from a file path's extension.
     *
     * @param path the file path
     * @return the matching format
     * @throws IllegalArgumentException if the extension is neither {@code .json} nor {@code .csv}
     */
    public static EventFileFormat fromPath(Path path) {
        String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
        for (EventFileFormat format : values()) {
            if (name.endsWith(format.extension)) {
                return format;
            }
        }
        throw new IllegalArgumentException(
                "Unsupported file extension for '" + path + "'; expected .json or .csv");
    }
}
