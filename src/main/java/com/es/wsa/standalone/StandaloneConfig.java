package com.es.wsa.standalone;

import com.es.wsa.storage.SecurityEventDocument;
import com.es.wsa.storage.SecurityEventRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.data.elasticsearch.core.ElasticsearchOperations;
import org.springframework.data.elasticsearch.core.IndexOperations;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;

/**
 * Supplies in-memory stand-ins for the Elasticsearch- and Redis-typed beans that the
 * (unmodified) production components still require to <em>construct</em> under the
 * {@code standalone} profile, where the real ES/Redis auto-configuration is excluded.
 *
 * <p>Nothing here participates in the actual read/write paths — the {@code @Primary} in-memory
 * {@code EventStorageService} / {@code StatsService} / {@code SamplesService} /
 * {@code IpRateTrackerService} beans win every functional injection. These beans exist only so
 * that:
 * <ul>
 *   <li>{@code ElasticsearchStorageServiceImpl}, {@code ElasticsearchStatsService} and
 *       {@code ElasticsearchSamplesService} (unprofiled {@code @Service}s that merely store
 *       their dependency in the constructor) can be created without error;</li>
 *   <li>{@code SecurityEventIndexInitializer} (an {@code ApplicationRunner}) can be created and
 *       run — its {@code indexOps(...).exists()} returns {@code true}, so it no-ops at boot;</li>
 *   <li>{@code DevDataGenController} (active under {@code dev}, included by {@code standalone})
 *       can inject a {@code SecurityEventRepository} and a {@code StringRedisTemplate}, which its
 *       {@code /clear} endpoint drives against the in-memory store and rate tracker.</li>
 * </ul>
 *
 * <p>{@link ElasticsearchOperations} and {@link SecurityEventRepository} are large interfaces
 * of which only a handful of methods are ever invoked, so they are provided as JDK dynamic
 * proxies rather than hand-implemented.
 */
@Configuration
@Profile("standalone")
public class StandaloneConfig {

    /**
     * Stub {@link ElasticsearchOperations}. Only {@code indexOps(...)} is exercised (by
     * {@code SecurityEventIndexInitializer}); it returns a nested stub whose {@code exists()}
     * is {@code true} so the initializer returns immediately without touching Elasticsearch.
     * Every other method returns a type-appropriate default.
     */
    @Bean
    @Primary
    public ElasticsearchOperations elasticsearchOperations() {
        InvocationHandler handler = (proxy, method, args) -> {
            if ("indexOps".equals(method.getName())) {
                return indexOperationsStub();
            }
            return defaultReturn(method.getReturnType());
        };
        return (ElasticsearchOperations) Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[]{ElasticsearchOperations.class},
                handler);
    }

    /**
     * In-memory {@link SecurityEventRepository} proxy over {@link InMemoryEventStore}. Only
     * {@code count}, {@code deleteAll} and {@code save} are ever called (by
     * {@code DevDataGenController#clear} and, were it not shadowed by the {@code @Primary}
     * in-memory storage service, {@code ElasticsearchStorageServiceImpl}).
     */
    @Bean
    @Primary
    public SecurityEventRepository securityEventRepository(InMemoryEventStore store) {
        InvocationHandler handler = (proxy, method, args) -> switch (method.getName()) {
            case "count" -> store.count();
            case "deleteAll" -> {
                store.clear();
                yield null;
            }
            case "save" -> store.save((SecurityEventDocument) args[0]);
            case "toString" -> "InMemorySecurityEventRepository";
            case "hashCode" -> System.identityHashCode(proxy);
            case "equals" -> proxy == args[0];
            default -> defaultReturn(method.getReturnType());
        };
        return (SecurityEventRepository) Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[]{SecurityEventRepository.class},
                handler);
    }

    /**
     * In-memory {@link StringRedisTemplate} backed by the rate tracker, so
     * {@code DevDataGenController#clear} can enumerate and delete {@code ip_events:*} keys
     * without a real Redis.
     */
    @Bean
    @Primary
    public StringRedisTemplate stringRedisTemplate(InMemoryIpRateTracker tracker) {
        return new InMemoryStringRedisTemplate(tracker);
    }

    /** Nested stub whose {@code exists()} is {@code true} so the index initializer no-ops. */
    private IndexOperations indexOperationsStub() {
        InvocationHandler handler = (proxy, method, args) -> switch (method.getName()) {
            case "exists" -> true;
            case "createWithMapping", "create" -> true;
            case "toString" -> "InMemoryIndexOperations";
            case "hashCode" -> System.identityHashCode(proxy);
            case "equals" -> proxy == args[0];
            default -> defaultReturn(method.getReturnType());
        };
        return (IndexOperations) Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[]{IndexOperations.class},
                handler);
    }

    /** Type-appropriate default for a proxied method's return type (zero/false/null). */
    private static Object defaultReturn(Class<?> type) {
        if (!type.isPrimitive()) {
            return null;
        }
        if (type == boolean.class) {
            return false;
        }
        if (type == long.class) {
            return 0L;
        }
        if (type == int.class) {
            return 0;
        }
        if (type == double.class) {
            return 0.0d;
        }
        if (type == float.class) {
            return 0.0f;
        }
        if (type == short.class) {
            return (short) 0;
        }
        if (type == byte.class) {
            return (byte) 0;
        }
        if (type == char.class) {
            return (char) 0;
        }
        // void.class
        return null;
    }
}
