package org.praxisplatform.authz.contracts.digest;

import java.util.Objects;

/**
 * Level 4 of the 4-level OPA runtime lineage: packaged and activated runtime release ({@code OPA-GEN-004}).
 *
 * @param releaseId unique release identifier
 * @param runtimeRevision operational runtime revision identifier
 * @param headEtag strong ETag of the active head selection
 * @param activationRevision monotonic activation counter (increments on rollbacks too)
 * @param policySetDigest stage 7 policy set digest
 * @param bundleArtifactDigest stage 8 SHA-256 digest of the packaged OPA bundle archive
 * @param compilerProfileVersion compiler profile version
 * @param compositionManifest embedded composition manifest
 */
public record OpaRuntimeRelease(
        String releaseId,
        String runtimeRevision,
        String headEtag,
        long activationRevision,
        String policySetDigest,
        String bundleArtifactDigest,
        String compilerProfileVersion,
        OpaRuntimeCompositionManifest compositionManifest
) {

    /** Validates release identity, digests, and positive activation revision. */
    public OpaRuntimeRelease {
        releaseId = requireNonBlank(releaseId, "releaseId");
        runtimeRevision = requireNonBlank(runtimeRevision, "runtimeRevision");
        headEtag = requireNonBlank(headEtag, "headEtag");
        if (activationRevision < 1) {
            throw new IllegalArgumentException("activationRevision must be positive");
        }
        policySetDigest = requireNonBlank(policySetDigest, "policySetDigest");
        bundleArtifactDigest = requireNonBlank(bundleArtifactDigest, "bundleArtifactDigest");
        compilerProfileVersion = requireNonBlank(compilerProfileVersion, "compilerProfileVersion");
        compositionManifest = Objects.requireNonNull(compositionManifest, "compositionManifest is required");
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
