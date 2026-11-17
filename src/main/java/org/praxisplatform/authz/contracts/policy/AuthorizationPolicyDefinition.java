package org.praxisplatform.authz.contracts.policy;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.context.FactDescriptor;
import org.praxisplatform.authz.contracts.digest.OpaProviderIoSchemas;

/**
 * Canonical authorization policy definition stored inside {@code DomainRuleDefinition}
 * ({@code ruleType = "authorization_policy"}, {@code schemaVersion = "praxis.authorization-policy/v1"},
 * {@code CC01}).
 *
 * @param schemaVersion canonical schema version ({@link #SCHEMA_VERSION_V1})
 * @param policyId unique policy identifier
 * @param version semantic version
 * @param title human-readable policy title
 * @param description domain description
 * @param policyPurposes semantic policy purpose tags
 * @param legalPurpose canonical {@code LegalTreatmentPurpose} name
 * @param legalBasisRef legal basis reference
 * @param combiningProfileRef combining profile reference ({@code praxis.authorization-combining/v1})
 * @param targets non-empty list of target specifications
 * @param dualScopeDelegation optional dual-scope functional delegation specification ({@code origin} vs {@code destination})
 * @param factRequirements declared fact requirements
 * @param rules non-empty list of authorization policy rules
 * @param materializationTargets non-empty list of materialization targets
 */
public record AuthorizationPolicyDefinition(
        String schemaVersion,
        String policyId,
        String version,
        String title,
        String description,
        Set<String> policyPurposes,
        String legalPurpose,
        String legalBasisRef,
        String combiningProfileRef,
        List<PolicyTargetSpec> targets,
        DualScopeDelegationSpec dualScopeDelegation,
        List<PolicyFactRequirement> factRequirements,
        List<AuthorizationPolicyRule> rules,
        List<PolicyMaterializationTargetSpec> materializationTargets
) {

    /** Canonical schema version for {@link AuthorizationPolicyDefinition}. */
    public static final String SCHEMA_VERSION_V1 = "praxis.authorization-policy/v1";

    /** Validates schema version, legalPurpose vocabulary, combining profile, targets, rules, and materialization targets. */
    public AuthorizationPolicyDefinition {
        schemaVersion = requireNonBlank(schemaVersion, "schemaVersion");
        if (!SCHEMA_VERSION_V1.equals(schemaVersion)) {
            throw new IllegalArgumentException("Unsupported AuthorizationPolicyDefinition schemaVersion: " + schemaVersion);
        }
        policyId = requireNonBlank(policyId, "policyId");
        version = requireNonBlank(version, "version");
        title = requireNonBlank(title, "title");
        description = requireNonBlank(description, "description");
        policyPurposes = policyPurposes == null ? Set.of() : Set.copyOf(policyPurposes);
        legalPurpose = requireNonBlank(legalPurpose, "legalPurpose");
        if (!FactDescriptor.ALLOWED_LEGAL_PURPOSES.contains(legalPurpose)) {
            throw new IllegalArgumentException(
                    "Unsupported legalPurpose '" + legalPurpose + "'; must be one of " + FactDescriptor.ALLOWED_LEGAL_PURPOSES);
        }
        legalBasisRef = requireNonBlank(legalBasisRef, "legalBasisRef");
        combiningProfileRef = requireNonBlank(combiningProfileRef, "combiningProfileRef");
        if (!OpaProviderIoSchemas.COMBINING_PROFILE_V1.equals(combiningProfileRef)) {
            throw new IllegalArgumentException("Unsupported combiningProfileRef: " + combiningProfileRef);
        }
        Objects.requireNonNull(targets, "targets is required");
        if (targets.isEmpty()) {
            throw new IllegalArgumentException("targets must not be empty");
        }
        targets = List.copyOf(targets);
        factRequirements = factRequirements == null ? List.of() : List.copyOf(factRequirements);
        Objects.requireNonNull(rules, "rules is required");
        if (rules.isEmpty()) {
            throw new IllegalArgumentException("rules must not be empty");
        }
        rules = List.copyOf(rules);
        Objects.requireNonNull(materializationTargets, "materializationTargets is required");
        if (materializationTargets.isEmpty()) {
            throw new IllegalArgumentException("materializationTargets must not be empty");
        }
        materializationTargets = List.copyOf(materializationTargets);
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
