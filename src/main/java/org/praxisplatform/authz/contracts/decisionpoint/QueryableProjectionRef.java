package org.praxisplatform.authz.contracts.decisionpoint;

import java.util.Objects;

/**
 * Digest-pinned reference to a {@link org.praxisplatform.authz.contracts.datascope.QueryableResourceProjection}.
 *
 * @param projectionId identifier of the queryable resource projection
 * @param projectionDigest SHA-256 digest of the queryable resource projection
 */
public record QueryableProjectionRef(String projectionId, String projectionDigest) {

    /** Validates non-blank identifier and digest. */
    public QueryableProjectionRef {
        projectionId = requireNonBlank(projectionId, "projectionId");
        projectionDigest = requireNonBlank(projectionDigest, "projectionDigest");
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
