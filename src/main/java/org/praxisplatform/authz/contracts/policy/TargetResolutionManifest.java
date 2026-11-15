package org.praxisplatform.authz.contracts.policy;

import java.util.List;
import java.util.Objects;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointRef;

/**
 * Immutable publication-time resolution manifest of a {@link PolicyTargetSpec} ({@code PDP-TGT-003..008}).
 *
 * @param targetId target identifier from {@link PolicyTargetSpec}
 * @param selectorDigest SHA-256 digest of the target specification
 * @param resolvedPointRefs ordered list of resolved {@link DecisionPointRef}s
 * @param resolvedSetDigest SHA-256 digest of the resolved set of decision points
 */
public record TargetResolutionManifest(
        String targetId,
        String selectorDigest,
        List<DecisionPointRef> resolvedPointRefs,
        String resolvedSetDigest
) {

    /** Validates non-empty resolved point refs and digests. */
    public TargetResolutionManifest {
        targetId = requireNonBlank(targetId, "targetId");
        selectorDigest = requireNonBlank(selectorDigest, "selectorDigest");
        Objects.requireNonNull(resolvedPointRefs, "resolvedPointRefs is required");
        if (resolvedPointRefs.isEmpty()) {
            throw new IllegalArgumentException("resolvedPointRefs must not be empty");
        }
        resolvedPointRefs = List.copyOf(resolvedPointRefs);
        resolvedSetDigest = requireNonBlank(resolvedSetDigest, "resolvedSetDigest");
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
