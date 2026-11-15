package org.praxisplatform.authz.contracts.digest;

import java.util.List;
import java.util.Objects;

/**
 * Level 2 of the 4-level OPA runtime lineage: composition manifest combining compiled policy units
 * with the platform-owned system combining module ({@code praxis/authz/system/combining.rego}, {@code OPA-GEN-002}).
 *
 * @param compositionId unique composition identifier
 * @param combiningProfileRef combining profile identifier (e.g. {@code praxis.authorization-combining/v1})
 * @param systemCombiningModuleDigest digest of {@code praxis/authz/system/combining.rego}
 * @param policyUnits ordered list of compiled policy unit manifests
 * @param compositionDigest stage 6 digest of this composition manifest
 */
public record OpaRuntimeCompositionManifest(
        String compositionId,
        String combiningProfileRef,
        String systemCombiningModuleDigest,
        List<OpaPolicyUnitManifest> policyUnits,
        String compositionDigest
) {

    /** Validates required composition fields and normalizes policy units. */
    public OpaRuntimeCompositionManifest {
        compositionId = requireNonBlank(compositionId, "compositionId");
        combiningProfileRef = requireNonBlank(combiningProfileRef, "combiningProfileRef");
        systemCombiningModuleDigest = requireNonBlank(systemCombiningModuleDigest, "systemCombiningModuleDigest");
        Objects.requireNonNull(policyUnits, "policyUnits is required");
        if (policyUnits.isEmpty()) {
            throw new IllegalArgumentException("policyUnits must not be empty");
        }
        policyUnits = List.copyOf(policyUnits);
        compositionDigest = requireNonBlank(compositionDigest, "compositionDigest");
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
