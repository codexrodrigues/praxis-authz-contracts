package org.praxisplatform.authz.contracts.policy;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * {@code MASK} capability contribution inside {@link AuthorizationRuleContributions} ({@code CC01}, {@code CC09}).
 *
 * @param fieldSelector field selector targeting one or more attributes
 * @param strategyId registered strategy identifier in {@code MaskStrategyRegistry}
 * @param parameters immutable strategy parameters
 */
public record MaskContributionSpec(
        PolicyFieldSelector fieldSelector,
        String strategyId,
        Map<String, Object> parameters
) {

    /** Validates non-null selector, non-blank strategyId, and wraps parameters. */
    public MaskContributionSpec {
        fieldSelector = Objects.requireNonNull(fieldSelector, "fieldSelector is required");
        Objects.requireNonNull(strategyId, "strategyId is required");
        strategyId = strategyId.trim();
        if (strategyId.isEmpty()) {
            throw new IllegalArgumentException("strategyId must not be blank");
        }
        parameters = parameters == null
                ? Map.of()
                : Collections.unmodifiableMap(new LinkedHashMap<>(parameters));
    }
}
