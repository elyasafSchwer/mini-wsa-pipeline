package com.es.wsa.datagen;

import com.es.wsa.domain.SecurityEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SequenceWriter;
import com.fasterxml.jackson.dataformat.csv.CsvSchema;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * Writes generated {@link SecurityEvent}s to disk as JSON or CSV. A plain helper class (not
 * a Spring bean); it owns an {@link ObjectMapper} configured to match the server's.
 *
 * <ul>
 *   <li>JSON — a pretty-printed array of nested event objects, byte-for-byte the shape the
 *       ingestion API accepts ({@code OffsetDateTime} is ISO-8601).</li>
 *   <li>CSV — a header row plus one flattened row per event, via {@link EventCsvMapper}.</li>
 * </ul>
 *
 * Parent directories are created as needed.
 */
public class EventFileWriter {

    private static final Logger log = LoggerFactory.getLogger(EventFileWriter.class);

    private final ObjectMapper objectMapper;
    private final EventCsvMapper csvMapper;

    public EventFileWriter() {
        this(DataGenObjectMapper.create(), new EventCsvMapper());
    }

    public EventFileWriter(ObjectMapper objectMapper, EventCsvMapper csvMapper) {
        this.objectMapper = objectMapper;
        this.csvMapper = csvMapper;
    }

    /**
     * Writes the events to {@code path} in the given format.
     *
     * @param events the events to write
     * @param path   the destination file (parent dirs are created if missing)
     * @param format the on-disk format
     */
    public void write(List<SecurityEvent> events, Path path, EventFileFormat format) {
        try {
            if (path.getParent() != null) {
                Files.createDirectories(path.getParent());
            }
            switch (format) {
                case JSON -> writeJson(events, path);
                case CSV -> writeCsv(events, path);
            }
            log.info("Wrote {} event(s) to {} ({})", events.size(), path, format);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to write events to " + path, e);
        }
    }

    private void writeJson(List<SecurityEvent> events, Path path) throws IOException {
        objectMapper.writerWithDefaultPrettyPrinter().writeValue(path.toFile(), events);
    }

    private void writeCsv(List<SecurityEvent> events, Path path) throws IOException {
        CsvSchema schema = csvMapper.schema();
        try (Writer out = Files.newBufferedWriter(path, StandardCharsets.UTF_8);
             SequenceWriter rows = csvMapper.csvMapper().writer(schema).writeValues(out)) {
            for (SecurityEvent event : events) {
                Map<String, String> row = csvMapper.toRow(event);
                rows.write(row);
            }
        }
    }
}
