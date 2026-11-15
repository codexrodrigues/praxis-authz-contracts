package org.praxisplatform.authz.contracts.decisionpoint;

import java.util.Objects;

/**
 * Digest-pinned reference to a request or response schema ({@code CanonicalSchemaRef} / {@code X-Schema-Hash}).
 *
 * @param schemaId canonical schema identifier
 * @param schemaHash SHA-256 schema hash
 */
public record SchemaDigestRef(String schemaId, String schemaHash) {

    /** Validates non-blank schema identifier and hash. */
    public SchemaDigestRef {
        schemaId = requireNonBlank(schemaId, "schemaId");
        schemaHash = requireNonBlank(schemaHash, "schemaHash");
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
