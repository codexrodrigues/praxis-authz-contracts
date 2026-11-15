package org.praxisplatform.authz.contracts.policy;

import java.util.Objects;

/**
 * Declares a materialization target for an {@link AuthorizationPolicyDefinition} ({@code CC01},
 * {@code OPA-UNT-001}).
 *
 * <p>Per {@code OPA-UNT-001}, {@code targetArtifactKey} must identify the stable compiled policy unit
 * ({@code unit:<policyId>:<version>}), never a raw decision point key.</p>
 *
 * @param targetLayer target execution layer (e.g. {@code policy_engine})
 * @param targetArtifactType target artifact type (e.g. {@code opa-policy})
 * @param targetArtifactKey stable policy unit key starting with {@code unit:}
 * @param compilerProfileRef compiler profile version reference
 */
public record PolicyMaterializationTargetSpec(
        String targetLayer,
        String targetArtifactType,
        String targetArtifactKey,
        String compilerProfileRef
) {

    /** Validates materialization target fields and enforces {@code OPA-UNT-001} on {@code targetArtifactKey}. */
    public PolicyMaterializationTargetSpec {
        targetLayer = requireNonBlank(targetLayer, "targetLayer");
        targetArtifactType = requireNonBlank(targetArtifactType, "targetArtifactType");
        targetArtifactKey = requireNonBlank(targetArtifactKey, "targetArtifactKey");
        if (!targetArtifactKey.startsWith("unit:")) {
            throw new IllegalArgumentException(
                    "targetArtifactKey must be a stable policy unit key starting with 'unit:' (OPA-UNT-001): " + targetArtifactKey);
        }
        compilerProfileRef = requireNonBlank(compilerProfileRef, "compilerProfileRef");
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
