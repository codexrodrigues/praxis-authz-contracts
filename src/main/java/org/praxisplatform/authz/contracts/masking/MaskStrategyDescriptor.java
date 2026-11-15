package org.praxisplatform.authz.contracts.masking;

import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.context.FactValueType;

/**
 * Descriptor of a server-side security masking strategy registered in {@link MaskStrategyRegistry}
 * ({@code CC09}, {@code ENF-MSK-001..008}).
 *
 * @param strategyId unique strategy identifier (e.g. {@code OMIT}, {@code NULLIFY}, {@code REDACT_CONSTANT})
 * @param severityRank algebraic severity rank (higher rank is strictly more restrictive)
 * @param supportedInputTypes supported field input types
 * @param outputType produced output type (or {@code null} for {@code OMIT}/{@code NULLIFY})
 * @param requiresNullableTargetField whether the target DTO field must declare {@code nullable = true}
 * @param allowedParameterNames allowed parameter keys
 */
public record MaskStrategyDescriptor(
        String strategyId,
        int severityRank,
        Set<FactValueType> supportedInputTypes,
        FactValueType outputType,
        boolean requiresNullableTargetField,
        Set<String> allowedParameterNames
) {

    /** Validates strategyId, positive severityRank, and non-empty supportedInputTypes. */
    public MaskStrategyDescriptor {
        Objects.requireNonNull(strategyId, "strategyId is required");
        strategyId = strategyId.trim();
        if (strategyId.isEmpty()) {
            throw new IllegalArgumentException("strategyId must not be blank");
        }
        if (severityRank <= 0) {
            throw new IllegalArgumentException("severityRank must be positive");
        }
        Objects.requireNonNull(supportedInputTypes, "supportedInputTypes is required");
        if (supportedInputTypes.isEmpty()) {
            throw new IllegalArgumentException("supportedInputTypes must not be empty");
        }
        supportedInputTypes = Set.copyOf(supportedInputTypes);
        allowedParameterNames = allowedParameterNames == null ? Set.of() : Set.copyOf(allowedParameterNames);
    }
}
