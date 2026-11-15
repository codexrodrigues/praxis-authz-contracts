package org.praxisplatform.authz.contracts.policy;

import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointKind;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;

/**
 * Target specification in an {@link AuthorizationPolicyDefinition} supporting both exact decision-point
 * pins and publication-time resolved selectors ({@code CC01}, {@code PDP-TGT-001..008}).
 *
 * @param targetId unique identifier of this target entry within the policy
 * @param kind {@link PolicyTargetSpecKind#EXACT} or {@link PolicyTargetSpecKind#SELECTOR}
 * @param pointKey canonical decision point key when {@code kind == EXACT}
 * @param expectedDescriptorDigest expected descriptor digest when {@code kind == EXACT}
 * @param selectorPointKinds point kinds matched when {@code kind == SELECTOR}
 * @param selectorResourceKeys resource keys matched when {@code kind == SELECTOR}
 * @param selectorOperationVerbs operation verbs matched when {@code kind == SELECTOR}
 * @param selectorGovernanceTags governance tags matched when {@code kind == SELECTOR}
 * @param evaluationModes evaluation modes governed on matched decision points
 */
public record PolicyTargetSpec(
        String targetId,
        PolicyTargetSpecKind kind,
        String pointKey,
        String expectedDescriptorDigest,
        Set<DecisionPointKind> selectorPointKinds,
        Set<String> selectorResourceKeys,
        Set<String> selectorOperationVerbs,
        Set<String> selectorGovernanceTags,
        Set<EvaluationMode> evaluationModes
) {

    /** Validates exact vs selector fields and non-empty evaluationModes. */
    public PolicyTargetSpec {
        targetId = requireNonBlank(targetId, "targetId");
        kind = Objects.requireNonNull(kind, "kind is required");
        selectorPointKinds = selectorPointKinds == null ? Set.of() : Set.copyOf(selectorPointKinds);
        selectorResourceKeys = selectorResourceKeys == null ? Set.of() : Set.copyOf(selectorResourceKeys);
        selectorOperationVerbs = selectorOperationVerbs == null ? Set.of() : Set.copyOf(selectorOperationVerbs);
        selectorGovernanceTags = selectorGovernanceTags == null ? Set.of() : Set.copyOf(selectorGovernanceTags);
        Objects.requireNonNull(evaluationModes, "evaluationModes is required");
        if (evaluationModes.isEmpty()) {
            throw new IllegalArgumentException("evaluationModes must not be empty");
        }
        evaluationModes = Set.copyOf(evaluationModes);
        if (kind == PolicyTargetSpecKind.EXACT) {
            pointKey = requireNonBlank(pointKey, "pointKey");
            expectedDescriptorDigest = requireNonBlank(expectedDescriptorDigest, "expectedDescriptorDigest");
        } else {
            if (selectorPointKinds.isEmpty()
                    && selectorResourceKeys.isEmpty()
                    && selectorOperationVerbs.isEmpty()
                    && selectorGovernanceTags.isEmpty()) {
                throw new IllegalArgumentException("SELECTOR target '" + targetId + "' must specify at least one selector criterion");
            }
        }
    }

    /** Convenience factory for an {@link PolicyTargetSpecKind#EXACT} target. */
    public static PolicyTargetSpec exact(
            String targetId,
            String pointKey,
            String expectedDescriptorDigest,
            Set<EvaluationMode> evaluationModes
    ) {
        return new PolicyTargetSpec(
                targetId,
                PolicyTargetSpecKind.EXACT,
                pointKey,
                expectedDescriptorDigest,
                Set.of(),
                Set.of(),
                Set.of(),
                Set.of(),
                evaluationModes
        );
    }

    /**
     * Returns a deterministic canonical preimage with lexicographically sorted set elements,
     * suitable for SHA-256 digest calculation across JVM processes ({@code BND-DIG-001}).
     */
    public String toCanonicalPreimage() {
        return "PolicyTargetSpec[targetId=" + targetId
                + ",kind=" + kind
                + ",pointKey=" + (pointKey == null ? "" : pointKey)
                + ",expectedDescriptorDigest=" + (expectedDescriptorDigest == null ? "" : expectedDescriptorDigest)
                + ",selectorPointKinds=" + selectorPointKinds.stream().map(Enum::name).sorted().toList()
                + ",selectorResourceKeys=" + selectorResourceKeys.stream().sorted().toList()
                + ",selectorOperationVerbs=" + selectorOperationVerbs.stream().sorted().toList()
                + ",selectorGovernanceTags=" + selectorGovernanceTags.stream().sorted().toList()
                + ",evaluationModes=" + evaluationModes.stream().map(Enum::name).sorted().toList()
                + "]";
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
