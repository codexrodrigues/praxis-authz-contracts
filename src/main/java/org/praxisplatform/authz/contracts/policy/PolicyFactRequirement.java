package org.praxisplatform.authz.contracts.policy;

import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;

/**
 * Declares a fact path required by an {@link AuthorizationPolicyDefinition} and the evaluation modes
 * in which it is required ({@code CC01}).
 *
 * @param factPath canonical SARC fact path
 * @param requiredInModes evaluation modes in which this fact is required
 */
public record PolicyFactRequirement(
        String factPath,
        Set<EvaluationMode> requiredInModes
) {

    /** Validates non-blank factPath and non-empty modes. */
    public PolicyFactRequirement {
        Objects.requireNonNull(factPath, "factPath is required");
        factPath = factPath.trim();
        if (factPath.isEmpty()) {
            throw new IllegalArgumentException("factPath must not be blank");
        }
        Objects.requireNonNull(requiredInModes, "requiredInModes is required");
        if (requiredInModes.isEmpty()) {
            throw new IllegalArgumentException("requiredInModes must not be empty");
        }
        requiredInModes = Set.copyOf(requiredInModes);
    }
}
