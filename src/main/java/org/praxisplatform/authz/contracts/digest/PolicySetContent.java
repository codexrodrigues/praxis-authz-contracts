package org.praxisplatform.authz.contracts.digest;

import java.util.Objects;

/**
 * Level 3 of the 4-level OPA runtime lineage: immutable policy set content bound to an environment
 * ({@code OPA-GEN-003}).
 *
 * @param policySetId policy set identifier
 * @param environmentKey target environment or tenant scope key
 * @param compositionDigest stage 6 composition digest
 * @param policySetDigest stage 7 policy set digest
 */
public record PolicySetContent(
        String policySetId,
        String environmentKey,
        String compositionDigest,
        String policySetDigest
) {

    /** Validates non-blank fields. */
    public PolicySetContent {
        policySetId = requireNonBlank(policySetId, "policySetId");
        environmentKey = requireNonBlank(environmentKey, "environmentKey");
        compositionDigest = requireNonBlank(compositionDigest, "compositionDigest");
        policySetDigest = requireNonBlank(policySetDigest, "policySetDigest");
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
