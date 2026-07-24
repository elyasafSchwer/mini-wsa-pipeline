package com.es.wsa.storage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.data.elasticsearch.core.ElasticsearchOperations;
import org.springframework.data.elasticsearch.core.IndexOperations;
import org.springframework.stereotype.Component;

/**
 * Ensures the {@code security-events} index exists <em>with the mapping declared on</em>
 * {@link SecurityEventDocument} before any event is written.
 *
 * <h2>Why this is needed</h2>
 * Elasticsearch auto-creates a missing index on first write using <strong>dynamic
 * mapping</strong>, which infers {@code String} fields as {@code text} (+ a {@code .keyword}
 * sub-field). That is wrong for this app: fields like {@code ruleCategory},
 * {@code ruleAction} and {@code clientIp} are declared as {@code keyword}/{@code ip} so they
 * can be aggregated and filtered. If the very first ingest lands before Spring Data applies
 * the annotated mapping, the index is created dynamically and the stats terms-aggregations
 * fail at query time with <em>"Fielddata is disabled on [ruleCategory]"</em>
 * ({@code search_phase_execution_exception}).
 *
 * <p>Creating the index up-front with {@link IndexOperations#createWithMapping()} pins the
 * correct field types regardless of write timing, eliminating that class of mapping drift.
 *
 * <h2>Behaviour</h2>
 * <ul>
 *   <li>If the index already exists, this does nothing (it never rewrites or migrates an
 *       existing mapping — that would require a reindex).</li>
 *   <li>If Elasticsearch is unreachable at startup, the failure is logged and swallowed so
 *       the application still boots; the index will simply be (re)created on a later run.</li>
 * </ul>
 */
@Component
public class SecurityEventIndexInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(SecurityEventIndexInitializer.class);

    private final ElasticsearchOperations operations;

    public SecurityEventIndexInitializer(ElasticsearchOperations operations) {
        this.operations = operations;
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            IndexOperations indexOps = operations.indexOps(SecurityEventDocument.class);
            if (indexOps.exists()) {
                log.debug("Index 'security-events' already exists; leaving its mapping unchanged");
                return;
            }
            indexOps.createWithMapping();
            log.info("Created Elasticsearch index 'security-events' with the SecurityEventDocument mapping");
        } catch (RuntimeException ex) {
            // Non-fatal: ES may be down at boot. Log and continue; the app can still start,
            // and the index will be created on a subsequent startup (or first write).
            log.warn("Could not ensure 'security-events' index mapping at startup ({}). "
                    + "It will be created on first availability.", ex.getMessage());
        }
    }
}
