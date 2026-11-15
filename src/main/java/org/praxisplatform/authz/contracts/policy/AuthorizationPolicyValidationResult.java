package org.praxisplatform.authz.contracts.policy;

import java.util.List;
import java.util.Map;

/**
 * Result of validating a candidate {@link AuthorizationPolicyDefinition} ({@code CC01}, {@code CC02}).
 *
 * @param valid {@code true} iff no {@code ERROR}-level diagnostics were produced
 * @param resolvedTargets publication-time resolved {@link TargetResolutionManifest}s
 * @param resolvedFieldSelectors publication-time resolved {@link FieldResolutionManifest}s keyed by selector digest
 * @param diagnostics ordered list of validation diagnostics
 */
public record AuthorizationPolicyValidationResult(
        boolean valid,
        List<TargetResolutionManifest> resolvedTargets,
        Map<String, FieldResolutionManifest> resolvedFieldSelectors,
        List<PolicyValidationDiagnostic> diagnostics
) {

    /** Normalizes collections to immutable copies. */
    public AuthorizationPolicyValidationResult {
        resolvedTargets = resolvedTargets == null ? List.of() : List.copyOf(resolvedTargets);
        resolvedFieldSelectors = resolvedFieldSelectors == null ? Map.of() : Map.copyOf(resolvedFieldSelectors);
        diagnostics = diagnostics == null ? List.of() : List.copyOf(diagnostics);
    }
}
