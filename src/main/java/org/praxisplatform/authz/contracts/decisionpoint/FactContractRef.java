package org.praxisplatform.authz.contracts.decisionpoint;

import java.util.Objects;

/**
 * Digest-pinned reference to a {@link org.praxisplatform.authz.contracts.context.FactContract}.
 *
 * @param factContractId identifier of the referenced {@code FactContract}
 * @param factContractDigest SHA-256 digest of the referenced {@code FactContract}
 */
public record FactContractRef(String factContractId, String factContractDigest) {

    /** Validates non-blank identifier and digest. */
    public FactContractRef {
        factContractId = requireNonBlank(factContractId, "factContractId");
        factContractDigest = requireNonBlank(factContractDigest, "factContractDigest");
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
