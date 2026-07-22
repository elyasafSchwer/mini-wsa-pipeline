package com.es.wsa.validation;

import com.es.wsa.config.WsaPolicyProperties;
import com.es.wsa.domain.Rule;
import com.es.wsa.domain.SecurityEvent;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * Validates incoming {@link SecurityEvent}s before they are published downstream.
 *
 * <p>Validation is performed manually (rather than via Bean Validation annotations) so
 * that the rules — including the configuration-driven attack-category check — live in
 * one auditable place. All problems are accumulated and returned together so the API can
 * report a complete picture of what is wrong with a payload.
 *
 * <p>The set of acceptable {@code rule.category} values is not hard-coded; it is the set
 * of category <em>keys</em> loaded at startup from {@link WsaPolicyProperties}
 * ({@code wsa.policies.categories} in {@code wsa-policies.yml}).
 */
@Component
public class SecurityEventValidator {

    private final WsaPolicyProperties policies;

    public SecurityEventValidator(WsaPolicyProperties policies) {
        this.policies = policies;
    }

    /**
     * Validates a single event.
     *
     * @param event the event to validate (may be {@code null})
     * @return a {@link ValidationResult}; {@link ValidationResult#valid()} is {@code true}
     * only when no problems were found
     */
    public ValidationResult validate(SecurityEvent event) {
        if (event == null) {
            return ValidationResult.of(List.of("event must not be null"));
        }

        List<String> errors = new ArrayList<>();

        requireText(errors, "eventId", event.eventId());
        requireNonNull(errors, "timestamp", event.timestamp());
        requireNonNull(errors, "configId", event.configId());
        requireText(errors, "clientIp", event.clientIp());
        requireText(errors, "hostname", event.hostname());
        requireText(errors, "path", event.path());
        requireText(errors, "method", event.method());
        requireNonNull(errors, "statusCode", event.statusCode());

        validateRule(errors, event.rule());

        return ValidationResult.of(errors);
    }

    private void validateRule(List<String> errors, Rule rule) {
        if (rule == null) {
            errors.add("rule is required");
            return;
        }
        requireText(errors, "rule.id", rule.id());
        requireText(errors, "rule.name", rule.name());
        requireNonNull(errors, "rule.severity", rule.severity());
        requireNonNull(errors, "rule.action", rule.action());

        // Attack category: required, and must be one of the configured category keys.
        String category = rule.category();
        if (!StringUtils.hasText(category)) {
            errors.add("rule.category is required");
        } else if (!policies.isAllowedCategory(category)) {
            errors.add("rule.category '" + category + "' is not an allowed attack category; allowed: "
                    + policies.categoryKeys());
        }
    }

    private static void requireText(List<String> errors, String field, String value) {
        if (!StringUtils.hasText(value)) {
            errors.add(field + " is required");
        }
    }

    private static void requireNonNull(List<String> errors, String field, Object value) {
        if (value == null) {
            errors.add(field + " is required");
        }
    }
}
