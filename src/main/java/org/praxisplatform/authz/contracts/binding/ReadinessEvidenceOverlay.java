package org.praxisplatform.authz.contracts.binding;

import java.time.Instant;
import java.util.Set;

/**
 * Derived runtime/deployment readiness overlay attached to a {@link RuntimeEnforcementBinding}
 * ({@code decision-platform-architecture-baseline-v1.md} §11, {@code ENF-READY-001..004}).
 *
 * @param verifiedStages set of verified readiness stages
 * @param activeRuntimeRevision active provider runtime revision
 * @param activePolicySetDigest active policy set digest
 * @param verifiedAt timestamp when readiness was verified
 */
public record ReadinessEvidenceOverlay(
        Set<ReadinessStage> verifiedStages,
        String activeRuntimeRevision,
        String activePolicySetDigest,
        Instant verifiedAt
) {

    /** All 4 required readiness stages for authoritative execution. */
    public static final Set<ReadinessStage> ALL_STAGES = Set.of(
            ReadinessStage.STRUCTURAL_READY,
            ReadinessStage.POLICY_READY,
            ReadinessStage.PROVIDER_READY,
            ReadinessStage.ENFORCEMENT_READY
    );

    /** Normalizes verified stages to an immutable set. */
    public ReadinessEvidenceOverlay {
        verifiedStages = verifiedStages == null ? Set.of() : Set.copyOf(verifiedStages);
    }

    /** Returns {@code true} iff all 4 readiness stages are verified. */
    public boolean isAuthoritativeReady() {
        return verifiedStages.containsAll(ALL_STAGES);
    }
}
