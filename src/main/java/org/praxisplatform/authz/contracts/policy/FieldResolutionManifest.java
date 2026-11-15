package org.praxisplatform.authz.contracts.policy;

import java.util.Objects;
import java.util.Set;

/**
 * Immutable publication-time resolution manifest of a {@link PolicyFieldSelector} ({@code PDP-FLD-004..007}).
 *
 * @param selectorDigest SHA-256 digest of the field selector
 * @param resolvedAttributeIds resolved canonical {@code attributeId}s
 * @param resolvedSetDigest SHA-256 digest of the resolved attribute set
 */
public record FieldResolutionManifest(
        String selectorDigest,
        Set<String> resolvedAttributeIds,
        String resolvedSetDigest
) {

    /** Validates non-empty resolved attributes and digests. */
    public FieldResolutionManifest {
        selectorDigest = requireNonBlank(selectorDigest, "selectorDigest");
        Objects.requireNonNull(resolvedAttributeIds, "resolvedAttributeIds is required");
        if (resolvedAttributeIds.isEmpty()) {
            throw new IllegalArgumentException("resolvedAttributeIds must not be empty");
        }
        resolvedAttributeIds = Set.copyOf(resolvedAttributeIds);
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
