package org.praxisplatform.authz.contracts.compatibility;

import java.util.Objects;

/**
 * Single decision-point compatibility entry published inside a {@link HostPolicyCompatibilityManifest}
 * ({@code CC08}).
 *
 * @param pointKey canonical decision point key
 * @param descriptorDigest SHA-256 digest of the decision point descriptor
 * @param factContractId governing fact contract identifier
 * @param factContractDigest SHA-256 digest of the governing fact contract
 * @param queryProjectionRef optional queryable resource projection identifier
 * @param queryProjectionDigest optional queryable resource projection digest
 * @param bindingDigest SHA-256 digest of the static {@code RuntimeEnforcementBinding}
 * @param activationStrategy rollout activation strategy
 * @param enforcementReady whether all 4 readiness stages are verified
 */
public record DecisionPointCompatibilityEntry(
        String pointKey,
        String descriptorDigest,
        String factContractId,
        String factContractDigest,
        String queryProjectionRef,
        String queryProjectionDigest,
        String bindingDigest,
        RolloutActivationStrategy activationStrategy,
        boolean enforcementReady
) {

    /** Validates required digests and activation strategy. */
    public DecisionPointCompatibilityEntry {
        pointKey = requireNonBlank(pointKey, "pointKey");
        descriptorDigest = requireNonBlank(descriptorDigest, "descriptorDigest");
        factContractId = requireNonBlank(factContractId, "factContractId");
        factContractDigest = requireNonBlank(factContractDigest, "factContractDigest");
        queryProjectionRef = normalizeOptional(queryProjectionRef);
        queryProjectionDigest = normalizeOptional(queryProjectionDigest);
        if ((queryProjectionRef == null) != (queryProjectionDigest == null)) {
            throw new IllegalArgumentException(
                    "queryProjectionRef and queryProjectionDigest must either both be present or both be null");
        }
        bindingDigest = requireNonBlank(bindingDigest, "bindingDigest");
        activationStrategy = Objects.requireNonNull(activationStrategy, "activationStrategy is required");
    }

    private static String normalizeOptional(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
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
