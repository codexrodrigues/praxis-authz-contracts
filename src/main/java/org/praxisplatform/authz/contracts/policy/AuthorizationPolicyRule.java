package org.praxisplatform.authz.contracts.policy;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.envelope.ObligationDirective;

/**
 * Single rule inside an {@link AuthorizationPolicyDefinition} ({@code CC01}, {@code PDP-EFF-001..011}).
 *
 * <p>Per {@code PCB-ORDER-001}, numeric rule priority is forbidden; rules combine algebraically.</p>
 *
 * @param ruleId unique rule identifier within the policy
 * @param description human-readable domain description
 * @param evaluationModes evaluation modes in which this rule participates
 * @param when applicability condition governed by {@link ConditionProfileKind#AUTHORIZATION_TARGET_V1}
 * @param contributions primary capability contributions
 * @param obligations sibling list of verifiable obligations ({@code PDP-EFF-009})
 */
public record AuthorizationPolicyRule(
        String ruleId,
        String description,
        Set<EvaluationMode> evaluationModes,
        AuthorizationSourceCondition when,
        AuthorizationRuleContributions contributions,
        List<ObligationDirective> obligations
) {

    /** Validates rule identity, modes, condition profile, and contributions. */
    public AuthorizationPolicyRule {
        ruleId = requireNonBlank(ruleId, "ruleId");
        description = requireNonBlank(description, "description");
        Objects.requireNonNull(evaluationModes, "evaluationModes is required");
        if (evaluationModes.isEmpty()) {
            throw new IllegalArgumentException("evaluationModes must not be empty");
        }
        evaluationModes = Set.copyOf(evaluationModes);
        when = Objects.requireNonNull(when, "when condition is required");
        if (when.profile() != ConditionProfileKind.AUTHORIZATION_TARGET_V1) {
            throw new IllegalArgumentException(
                    "Rule 'when' condition must use profile AUTHORIZATION_TARGET_V1; SEARCH predicates belong in contributions.dataScope.resourceCondition");
        }
        contributions = Objects.requireNonNull(contributions, "contributions is required");
        if (evaluationModes.contains(EvaluationMode.SEARCH)
                && contributions.dataScope() == null
                && contributions.fieldUse().isEmpty()
                && contributions.mask().isEmpty()) {
            throw new IllegalArgumentException(
                    "Rule '" + ruleId + "' declaring SEARCH mode must contribute dataScope, fieldUse, or mask");
        }
        obligations = obligations == null ? List.of() : List.copyOf(obligations);
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
