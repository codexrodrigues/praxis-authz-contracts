package org.praxisplatform.authz.contracts.policy;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Source condition expression in {@code praxis-json-logic} governed by a {@link ConditionProfileKind}
 * ({@code CC02}, {@code PDP-COND-001..007}).
 *
 * @param language expression language identifier ({@link #LANGUAGE_PRAXIS_JSON_LOGIC})
 * @param profile deterministic condition profile ({@code authorization-target/v1} or {@code authorization-search-source/v1})
 * @param expression JSON Logic AST root map
 */
public record AuthorizationSourceCondition(
        String language,
        ConditionProfileKind profile,
        Map<String, Object> expression
) {

    /** Canonical language identifier for authorization conditions. */
    public static final String LANGUAGE_PRAXIS_JSON_LOGIC = "praxis-json-logic";

    /** Validates language, profile, and non-empty expression root. */
    public AuthorizationSourceCondition {
        Objects.requireNonNull(language, "language is required");
        language = language.trim();
        if (!LANGUAGE_PRAXIS_JSON_LOGIC.equals(language)) {
            throw new IllegalArgumentException(
                    "Unsupported condition language '" + language + "'; expected '" + LANGUAGE_PRAXIS_JSON_LOGIC + "'");
        }
        profile = Objects.requireNonNull(profile, "profile is required");
        Objects.requireNonNull(expression, "expression is required");
        if (expression.isEmpty()) {
            throw new IllegalArgumentException("expression must not be empty");
        }
        expression = Collections.unmodifiableMap(new LinkedHashMap<>(expression));
    }
}
