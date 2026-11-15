package org.praxisplatform.authz.contracts.envelope;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Security mask directive targeting a canonical {@code attributeId} with a registered {@code strategyId}
 * ({@code CC07}, {@code CC09}).
 *
 * @param attributeId canonical {@code @DomainLineage.attributeId}
 * @param strategyId registered strategy identifier in {@code MaskStrategyRegistry}
 * @param parameters immutable strategy parameters
 */
public record MaskDirective(
        String attributeId,
        String strategyId,
        Map<String, Object> parameters
) {

    /** Validates non-blank attributeId and strategyId and wraps parameters as unmodifiable. */
    public MaskDirective {
        attributeId = requireNonBlank(attributeId, "attributeId");
        strategyId = requireNonBlank(strategyId, "strategyId");
        parameters = parameters == null
                ? Map.of()
                : Collections.unmodifiableMap(new LinkedHashMap<>(parameters));
    }

    private static String requireNonBlank(String value, String field) {
        Objects.requireNonNull(value, field + " is required");
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return trimmed;
    }
}
