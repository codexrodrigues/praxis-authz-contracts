package org.praxisplatform.authz.contracts.context;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Derived, persistence-neutral catalog of authorization facts for a resource or service scope ({@code CC04}).
 *
 * @param schemaVersion canonical schema version ({@link #SCHEMA_VERSION_V1})
 * @param factContractId stable identifier of this contract
 * @param version semantic version of this contract
 * @param factContractDigest canonical SHA-256 digest of this contract
 * @param resourceKey canonical resource key (or service key for non-resource points)
 * @param descriptorsByPath map of {@code factPath} to {@link FactDescriptor}
 */
public record FactContract(
        String schemaVersion,
        String factContractId,
        String version,
        String factContractDigest,
        String resourceKey,
        Map<String, FactDescriptor> descriptorsByPath
) {

    /** Canonical schema version for {@link FactContract}. */
    public static final String SCHEMA_VERSION_V1 = "praxis.fact-contract/v1";

    /** Validates schema version, digest, and map key consistency. */
    public FactContract {
        schemaVersion = requireNonBlank(schemaVersion, "schemaVersion");
        if (!SCHEMA_VERSION_V1.equals(schemaVersion)) {
            throw new IllegalArgumentException("Unsupported FactContract schemaVersion: " + schemaVersion);
        }
        factContractId = requireNonBlank(factContractId, "factContractId");
        version = requireNonBlank(version, "version");
        factContractDigest = requireNonBlank(factContractDigest, "factContractDigest");
        resourceKey = requireNonBlank(resourceKey, "resourceKey");
        Objects.requireNonNull(descriptorsByPath, "descriptorsByPath is required");
        if (descriptorsByPath.isEmpty()) {
            throw new IllegalArgumentException("descriptorsByPath must not be empty");
        }
        for (Map.Entry<String, FactDescriptor> entry : descriptorsByPath.entrySet()) {
            if (!entry.getKey().equals(entry.getValue().factPath())) {
                throw new IllegalArgumentException(
                        "Descriptor map key '" + entry.getKey() + "' does not match factPath '"
                                + entry.getValue().factPath() + "'");
            }
        }
        descriptorsByPath = Map.copyOf(descriptorsByPath);
    }

    /** Looks up a {@link FactDescriptor} by its canonical SARC path. */
    public Optional<FactDescriptor> findFact(String factPath) {
        return Optional.ofNullable(descriptorsByPath.get(factPath));
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
