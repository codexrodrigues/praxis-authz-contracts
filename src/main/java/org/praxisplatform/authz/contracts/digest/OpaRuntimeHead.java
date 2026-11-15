package org.praxisplatform.authz.contracts.digest;

import java.util.Objects;

/**
 * Runtime head document reported by an OPA instance at {@code /v1/data/praxis/authz/v1/runtime_head}
 * and used by the 3-step {@code SEARCH} same-instance revision guard ({@code CC11}, {@code OPA-SEARCH-001..004}).
 *
 * @param instanceId unique identifier of the serving OPA instance
 * @param runtimeRevision active runtime revision loaded in the instance
 * @param headEtag active head ETag
 * @param activationRevision monotonic activation counter
 * @param policySetDigest active policy set digest
 * @param bundleArtifactDigest active bundle archive digest
 * @param compilerProfileVersion compiler profile version
 * @param opaCapabilitiesDigest digest of the target OPA capabilities profile
 */
public record OpaRuntimeHead(
        String instanceId,
        String runtimeRevision,
        String headEtag,
        long activationRevision,
        String policySetDigest,
        String bundleArtifactDigest,
        String compilerProfileVersion,
        String opaCapabilitiesDigest
) {

    /** Validates non-blank head fields and positive activation revision. */
    public OpaRuntimeHead {
        instanceId = requireNonBlank(instanceId, "instanceId");
        runtimeRevision = requireNonBlank(runtimeRevision, "runtimeRevision");
        headEtag = requireNonBlank(headEtag, "headEtag");
        if (activationRevision < 1) {
            throw new IllegalArgumentException("activationRevision must be positive");
        }
        policySetDigest = requireNonBlank(policySetDigest, "policySetDigest");
        bundleArtifactDigest = requireNonBlank(bundleArtifactDigest, "bundleArtifactDigest");
        compilerProfileVersion = requireNonBlank(compilerProfileVersion, "compilerProfileVersion");
        opaCapabilitiesDigest = requireNonBlank(opaCapabilitiesDigest, "opaCapabilitiesDigest");
    }

    /**
     * Verifies the atomic invariant of the 3-step {@code SEARCH} protocol ({@code preflight -> compile -> postflight}):
     * both observations must come from the exact same OPA instance, runtime revision, and policy set digest
     * ({@code OPA-SEARCH-004}).
     *
     * @param preflightHead head observed during step 1 ({@code search_preflight})
     * @param postflightHead head observed during step 3 ({@code runtime_head})
     * @return {@code true} iff no instance or bundle rotation occurred during UCAST compilation
     */
    public static boolean verifySameInstanceSearchGuard(
            OpaRuntimeHead preflightHead,
            OpaRuntimeHead postflightHead
    ) {
        if (preflightHead == null || postflightHead == null) {
            return false;
        }
        return preflightHead.equals(postflightHead);
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
