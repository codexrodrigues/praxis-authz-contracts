package org.praxisplatform.authz.contracts.envelope;

import java.util.Objects;

/**
 * Audit trace of an individual policy unit contribution combined by the provider ({@code CC07}).
 *
 * @param policyUnitKey compiled policy unit key
 * @param policyId source policy identifier
 * @param ruleId matched rule identifier
 * @param authority contribution authority ({@code GRANT} or {@code RESTRICT})
 * @param accessEffect contributed access effect
 * @param reasonCode stable semantic reason code
 */
public record PolicyUnitContributionTrace(
        String policyUnitKey,
        String policyId,
        String ruleId,
        ContributionAuthority authority,
        RuleEffect accessEffect,
        String reasonCode
) {

    /** Validates required trace fields. */
    public PolicyUnitContributionTrace {
        policyUnitKey = requireNonBlank(policyUnitKey, "policyUnitKey");
        policyId = requireNonBlank(policyId, "policyId");
        ruleId = requireNonBlank(ruleId, "ruleId");
        authority = Objects.requireNonNull(authority, "authority is required");
        accessEffect = Objects.requireNonNull(accessEffect, "accessEffect is required");
        reasonCode = requireNonBlank(reasonCode, "reasonCode");
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
