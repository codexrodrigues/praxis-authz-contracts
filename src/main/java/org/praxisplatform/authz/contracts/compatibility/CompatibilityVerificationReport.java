package org.praxisplatform.authz.contracts.compatibility;

import java.util.List;
import java.util.Objects;

/**
 * Result of verifying a {@link HostPolicyCompatibilityManifest} against an
 * {@link org.praxisplatform.authz.contracts.digest.OpaRuntimeRelease} and {@link ImpactGraphBaseline} ({@code CC08}).
 *
 * @param compatible {@code true} iff no blocking mismatches exist
 * @param runtimeRevision verified runtime revision
 * @param policySetDigest verified policy set digest
 * @param impactCompletenessStatus impact graph completeness status
 * @param blockingMismatches ordered list of blocking mismatch codes/messages
 */
public record CompatibilityVerificationReport(
        boolean compatible,
        String runtimeRevision,
        String policySetDigest,
        ImpactCompletenessStatus impactCompletenessStatus,
        List<String> blockingMismatches
) {

    /** Validates consistency between {@code compatible} flag and {@code blockingMismatches}. */
    public CompatibilityVerificationReport {
        Objects.requireNonNull(runtimeRevision, "runtimeRevision is required");
        Objects.requireNonNull(policySetDigest, "policySetDigest is required");
        impactCompletenessStatus = Objects.requireNonNull(impactCompletenessStatus, "impactCompletenessStatus is required");
        blockingMismatches = blockingMismatches == null ? List.of() : List.copyOf(blockingMismatches);
        if (compatible && !blockingMismatches.isEmpty()) {
            throw new IllegalArgumentException("compatible=true report cannot contain blockingMismatches");
        }
    }
}
