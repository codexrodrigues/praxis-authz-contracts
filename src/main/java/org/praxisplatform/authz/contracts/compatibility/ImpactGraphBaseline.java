package org.praxisplatform.authz.contracts.compatibility;

import java.util.Objects;
import java.util.Set;

/**
 * Impact analysis graph baseline evaluated before activating or publishing a policy release
 * ({@code CC08}, {@code BND-IMP-001..004}).
 *
 * @param baselineId unique baseline identifier
 * @param completenessStatus completeness status of the impact graph
 * @param impactedPolicyUnitKeys impacted policy unit keys
 * @param impactedPointKeys impacted decision point keys
 * @param requiredMaskStrategyIds mask strategy IDs required by the policy set
 * @param requiredObligationTypes obligation types required by the policy set
 * @param blockingReasons blocking reasons if incomplete or incompatible
 */
public record ImpactGraphBaseline(
        String baselineId,
        ImpactCompletenessStatus completenessStatus,
        Set<String> impactedPolicyUnitKeys,
        Set<String> impactedPointKeys,
        Set<String> requiredMaskStrategyIds,
        Set<String> requiredObligationTypes,
        Set<String> blockingReasons
) {

    /** Validates baselineId and completenessStatus and normalizes sets. */
    public ImpactGraphBaseline {
        Objects.requireNonNull(baselineId, "baselineId is required");
        baselineId = baselineId.trim();
        if (baselineId.isEmpty()) {
            throw new IllegalArgumentException("baselineId must not be blank");
        }
        completenessStatus = Objects.requireNonNull(completenessStatus, "completenessStatus is required");
        impactedPolicyUnitKeys = impactedPolicyUnitKeys == null ? Set.of() : Set.copyOf(impactedPolicyUnitKeys);
        impactedPointKeys = impactedPointKeys == null ? Set.of() : Set.copyOf(impactedPointKeys);
        requiredMaskStrategyIds = requiredMaskStrategyIds == null ? Set.of() : Set.copyOf(requiredMaskStrategyIds);
        requiredObligationTypes = requiredObligationTypes == null ? Set.of() : Set.copyOf(requiredObligationTypes);
        blockingReasons = blockingReasons == null ? Set.of() : Set.copyOf(blockingReasons);
    }

    /**
     * Returns {@code true} iff {@code completenessStatus == COMPLETE} and {@code blockingReasons} is empty
     * ({@code BND-IMP-002}).
     */
    public boolean isPublishableForAuthoritativeExecution() {
        return completenessStatus == ImpactCompletenessStatus.COMPLETE && blockingReasons.isEmpty();
    }
}
