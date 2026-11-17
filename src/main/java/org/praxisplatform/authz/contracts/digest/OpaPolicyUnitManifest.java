package org.praxisplatform.authz.contracts.digest;

import java.util.Objects;
import java.util.Set;

/**
 * Level 1 of the 4-level OPA runtime lineage: manifest of a single compiled policy unit
 * ({@code OPA-GEN-001}, {@code OPA-UNT-001}).
 *
 * @param policyUnitKey stable policy unit key (e.g. {@code unit:pol-workforce-leave-requests-custody:v1})
 * @param policyId source policy identifier
 * @param policyVersion source policy version
 * @param regoPackagePath generated Rego package path (e.g. {@code praxis.authz.units.pol_workforce_leave_requests_v1})
 * @param digestChain 5-stage per-unit digest chain
 * @param targetPointKeys resolved canonical decision point keys governed by this unit
 */
public record OpaPolicyUnitManifest(
        String policyUnitKey,
        String policyId,
        String policyVersion,
        String regoPackagePath,
        PolicyDigestChain digestChain,
        Set<String> targetPointKeys
) {

    /** Validates unit key, Rego package namespace, digest chain, and non-empty target point keys. */
    public OpaPolicyUnitManifest {
        policyUnitKey = requireNonBlank(policyUnitKey, "policyUnitKey");
        if (!policyUnitKey.startsWith("unit:")) {
            throw new IllegalArgumentException("policyUnitKey must start with 'unit:' (OPA-UNT-001): " + policyUnitKey);
        }
        policyId = requireNonBlank(policyId, "policyId");
        policyVersion = requireNonBlank(policyVersion, "policyVersion");
        regoPackagePath = requireNonBlank(regoPackagePath, "regoPackagePath");
        if (!regoPackagePath.startsWith("praxis.authz.units.")) {
            throw new IllegalArgumentException(
                    "regoPackagePath must reside under 'praxis.authz.units.*': " + regoPackagePath);
        }
        digestChain = Objects.requireNonNull(digestChain, "digestChain is required");
        Objects.requireNonNull(targetPointKeys, "targetPointKeys is required");
        if (targetPointKeys.isEmpty()) {
            throw new IllegalArgumentException("targetPointKeys must not be empty");
        }
        targetPointKeys = Set.copyOf(targetPointKeys);
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
