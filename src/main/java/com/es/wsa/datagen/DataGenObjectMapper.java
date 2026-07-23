package com.es.wsa.datagen;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

/**
 * Builds an {@link ObjectMapper} configured to match Spring Boot's auto-configuration for
 * the data-generation tooling: the JSR-310 module registered and dates written as ISO-8601
 * strings rather than numeric timestamps.
 *
 * <p>Because the generator and feeder are plain classes (not Spring beans), they own their
 * own mapper via this factory so file output and ingestion payloads are byte-identical to
 * what the server produces and expects.
 */
final class DataGenObjectMapper {

    private DataGenObjectMapper() {
    }

    static ObjectMapper create() {
        return JsonMapper.builder()
                .addModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .build();
    }
}
