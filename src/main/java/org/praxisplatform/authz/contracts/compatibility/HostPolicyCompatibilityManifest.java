package org.praxisplatform.authz.contracts.compatibility;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Host-published compatibility manifest used for the bidirectional handshake between a host application
 * and an {@link org.praxisplatform.authz.contracts.digest.OpaRuntimeRelease} ({@code CC08}, {@code OPA-HANDSHAKE-001..005}).
 *
 * @param schemaVersion canonical schema version ({@link #SCHEMA_VERSION_V1})
 * @param hostApplicationId host application identifier
 * @param serviceKey authoritative service key
 * @param hostReleaseVersion host release version
 * @param generatedAt manifest generation timestamp
 * @param supportedProviderIoSchemas supported provider I/O schema versions
 * @param registeredMaskStrategyIds registered strategy IDs in the host's {@code MaskStrategyRegistry}
 * @param registeredObligationTypes registered obligation types in the host's {@code ObligationHandlerRegistry}
 * @param decisionPointBindings compatibility entries for bound decision points
 */
public record HostPolicyCompatibilityManifest(
        String schemaVersion,
        String hostApplicationId,
        String serviceKey,
        String hostReleaseVersion,
        Instant generatedAt,
        Set<String> supportedProviderIoSchemas,
        Set<String> registeredMaskStrategyIds,
        Set<String> registeredObligationTypes,
        List<DecisionPointCompatibilityEntry> decisionPointBindings
) {

    /** Canonical schema version for {@link HostPolicyCompatibilityManifest}. */
    public static final String SCHEMA_VERSION_V1 = "praxis.host-policy-compatibility/v1";

    /** Validates schema version, host identity, and non-empty bindings. */
    public HostPolicyCompatibilityManifest {
        schemaVersion = requireNonBlank(schemaVersion, "schemaVersion");
        if (!SCHEMA_VERSION_V1.equals(schemaVersion)) {
            throw new IllegalArgumentException(
                    "Unsupported HostPolicyCompatibilityManifest schemaVersion: " + schemaVersion);
        }
        hostApplicationId = requireNonBlank(hostApplicationId, "hostApplicationId");
        serviceKey = requireNonBlank(serviceKey, "serviceKey");
        hostReleaseVersion = requireNonBlank(hostReleaseVersion, "hostReleaseVersion");
        generatedAt = Objects.requireNonNull(generatedAt, "generatedAt is required");
        supportedProviderIoSchemas = supportedProviderIoSchemas == null
                ? Set.of()
                : Set.copyOf(supportedProviderIoSchemas);
        registeredMaskStrategyIds = registeredMaskStrategyIds == null
                ? Set.of()
                : Set.copyOf(registeredMaskStrategyIds);
        registeredObligationTypes = registeredObligationTypes == null
                ? Set.of()
                : Set.copyOf(registeredObligationTypes);
        Objects.requireNonNull(decisionPointBindings, "decisionPointBindings is required");
        decisionPointBindings = List.copyOf(decisionPointBindings);
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
