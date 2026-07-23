package com.es.wsa.datagen;

import com.es.wsa.domain.SecurityEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.CollectionType;
import com.fasterxml.jackson.dataformat.csv.CsvSchema;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Reads {@link SecurityEvent}s from a JSON or CSV file (format auto-detected from the file
 * extension via {@link EventFileFormat#fromPath(Path)}). A plain helper class (not a Spring
 * bean); it owns an {@link ObjectMapper} configured to match the server's.
 *
 * <p>The CSV path reverses {@link EventCsvMapper}'s flattening, rebuilding the nested
 * {@code rule} / {@code geoLocation} objects — so a file written by {@link EventFileWriter}
 * in either format round-trips back to equal events.
 */
public class EventFileReader {

    private static final Logger log = LoggerFactory.getLogger(EventFileReader.class);

    private final ObjectMapper objectMapper;
    private final EventCsvMapper csvMapper;

    public EventFileReader() {
        this(DataGenObjectMapper.create(), new EventCsvMapper());
    }

    public EventFileReader(ObjectMapper objectMapper, EventCsvMapper csvMapper) {
        this.objectMapper = objectMapper;
        this.csvMapper = csvMapper;
    }

    /**
     * Reads events from a file, detecting JSON vs CSV by extension.
     *
     * @param path the source file
     * @return the events contained in the file
     * @throws IllegalArgumentException if the extension is unsupported
     */
    public List<SecurityEvent> read(Path path) {
        EventFileFormat format = EventFileFormat.fromPath(path);
        try {
            List<SecurityEvent> events = switch (format) {
                case JSON -> readJson(path);
                case CSV -> readCsv(path);
            };
            log.info("Read {} event(s) from {} ({})", events.size(), path, format);
            return events;
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read events from " + path, e);
        }
    }

    private List<SecurityEvent> readJson(Path path) throws IOException {
        CollectionType type = objectMapper.getTypeFactory()
                .constructCollectionType(List.class, SecurityEvent.class);
        return objectMapper.readValue(path.toFile(), type);
    }

    private List<SecurityEvent> readCsv(Path path) throws IOException {
        CsvSchema schema = csvMapper.schema();
        List<SecurityEvent> events = new ArrayList<>();
        try (Reader in = Files.newBufferedReader(path, StandardCharsets.UTF_8);
             var iterator = csvMapper.csvMapper()
                     .readerForMapOf(String.class)
                     .with(schema)
                     .<Map<String, String>>readValues(in)) {
            while (iterator.hasNext()) {
                events.add(csvMapper.fromRow(iterator.next()));
            }
        }
        return events;
    }
}
