package org.praxisplatform.authz.contracts.authority;

import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.decisionpoint.PointAuthorityMode;
import org.praxisplatform.authz.contracts.envelope.ContributionAuthority;
import org.praxisplatform.authz.contracts.envelope.EnforcementDisposition;
import org.praxisplatform.authz.contracts.envelope.GateOutcome;
import org.praxisplatform.authz.contracts.envelope.ObligationDirective;
import org.praxisplatform.authz.contracts.envelope.PolicyUnitContributionTrace;
import org.praxisplatform.authz.contracts.envelope.ProviderEvaluationEnvelope;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;

/**
 * Converges {@code praxis-config-starter}'s {@code RuleAuthority} and {@code DomainRuleRolloutState}
 * onto the two orthogonal runtime axes ({@link ExecutionDispositionMode} and {@link PointAuthorityMode})
 * and implements the order-independent algebraic combining law ({@code CC12}, {@code PCB-AUTH-001..005},
 * {@code ENF-GEN-019..020}).
 *
 * @param legacyRuleAuthorityName name of {@code RuleAuthority} ({@code REFERENCE_ONLY}, {@code CAN_BLOCK_PROVEN_DENY}, {@code AUTHORITATIVE})
 * @param dispositionMode operational rollout mode
 * @param pointAuthorityMode semantic point authority mode ({@code RESTRICT_BASELINE} or {@code AUTHORITATIVE})
 */
public record EffectiveAuthorityBinding(
        String legacyRuleAuthorityName,
        ExecutionDispositionMode dispositionMode,
        PointAuthorityMode pointAuthorityMode
) {

    /** Closed vocabulary of legacy {@code RuleAuthority} names from {@code praxis-config-starter}. */
    public static final Set<String> ALLOWED_LEGACY_RULE_AUTHORITIES = Set.of(
            "REFERENCE_ONLY",
            "CAN_BLOCK_PROVEN_DENY",
            "AUTHORITATIVE"
    );

    /** Validates legacy authority convergence rules ({@code CC12} §3.6.2). */
    public EffectiveAuthorityBinding {
        Objects.requireNonNull(legacyRuleAuthorityName, "legacyRuleAuthorityName is required");
        legacyRuleAuthorityName = legacyRuleAuthorityName.trim();
        if (!ALLOWED_LEGACY_RULE_AUTHORITIES.contains(legacyRuleAuthorityName)) {
            throw new IllegalArgumentException(
                    "Unsupported legacyRuleAuthorityName '" + legacyRuleAuthorityName
                            + "'; must be one of " + ALLOWED_LEGACY_RULE_AUTHORITIES);
        }
        dispositionMode = Objects.requireNonNull(dispositionMode, "dispositionMode is required");
        pointAuthorityMode = Objects.requireNonNull(pointAuthorityMode, "pointAuthorityMode is required");
        if ("CAN_BLOCK_PROVEN_DENY".equals(legacyRuleAuthorityName)
                && pointAuthorityMode != PointAuthorityMode.RESTRICT_BASELINE) {
            throw new IllegalArgumentException(
                    "CAN_BLOCK_PROVEN_DENY must map exclusively to pointAuthorityMode=RESTRICT_BASELINE (PCB-AUTH-003)");
        }
        if ("REFERENCE_ONLY".equals(legacyRuleAuthorityName)
                && pointAuthorityMode != PointAuthorityMode.RESTRICT_BASELINE) {
            throw new IllegalArgumentException(
                    "REFERENCE_ONLY must map exclusively to pointAuthorityMode=RESTRICT_BASELINE");
        }
        if ("AUTHORITATIVE".equals(legacyRuleAuthorityName)
                && dispositionMode == ExecutionDispositionMode.AUTHORITATIVE_EXECUTION
                && pointAuthorityMode != PointAuthorityMode.AUTHORITATIVE) {
            throw new IllegalArgumentException(
                    "Active AUTHORITATIVE rule authority must map to pointAuthorityMode=AUTHORITATIVE");
        }
        if ("REFERENCE_ONLY".equals(legacyRuleAuthorityName)
                && dispositionMode == ExecutionDispositionMode.AUTHORITATIVE_EXECUTION) {
            throw new IllegalArgumentException(
                    "REFERENCE_ONLY rule authority cannot enter AUTHORITATIVE_EXECUTION");
        }
    }

    /** Returns {@code true} iff this binding is allowed to grant access beyond the static structural baseline. */
    public boolean canGrantAccessBeyondBaseline() {
        return dispositionMode == ExecutionDispositionMode.AUTHORITATIVE_EXECUTION
                && pointAuthorityMode == PointAuthorityMode.AUTHORITATIVE;
    }

    /**
     * Evaluates the canonical order-independent combining formula:
     * {@code EffectiveAccess = HardGuard ∩ GrantSurface ∩ Restrictions}, failing closed on any
     * non-{@code ALLOW} provider gate outcome or unresolved conflict ({@code PCB-AUTH-001}, {@code ENF-GEN-019..020}).
     *
     * @param hardGuardAllowed whether mandatory host hard guards (tenant/scope) allow the request
     * @param structuralBaselineAllowed whether the static host baseline allows the request
     * @param envelope provider evaluation envelope
     * @return final {@link EnforcementDisposition}
     */
    public EnforcementDisposition normalizeDisposition(
            boolean hardGuardAllowed,
            boolean structuralBaselineAllowed,
            ProviderEvaluationEnvelope envelope
    ) {
        Objects.requireNonNull(envelope, "envelope is required");
        if (!hardGuardAllowed) {
            return EnforcementDisposition.DENY;
        }
        if (dispositionMode == ExecutionDispositionMode.TEST
                || dispositionMode == ExecutionDispositionMode.PREFLIGHT) {
            throw new IllegalStateException(
                    dispositionMode + " policy binding cannot execute runtime enforcement (PCB-AUTH-002)");
        }
        if (dispositionMode == ExecutionDispositionMode.SHADOW) {
            // In SHADOW observation mode, dynamic policies are observed for telemetry/diff only
            // and can never grant access beyond structuralBaselineAllowed.
            return structuralBaselineAllowed ? EnforcementDisposition.PERMIT : EnforcementDisposition.DENY;
        }
        if (!envelope.unresolvedConflicts().isEmpty()) {
            return EnforcementDisposition.DENY;
        }
        if (envelope.gateOutcome() == GateOutcome.DENY
                || envelope.gateOutcome() == GateOutcome.INCONCLUSIVE
                || envelope.gateOutcome() == GateOutcome.TECHNICAL_ERROR) {
            return EnforcementDisposition.DENY;
        }

        boolean hasRestrictDeny = false;
        boolean hasExplicitGrantAllow = false;
        for (PolicyUnitContributionTrace trace : envelope.unitContributions()) {
            if (trace.accessEffect() == RuleEffect.DENY) {
                hasRestrictDeny = true;
            } else if (trace.authority() == ContributionAuthority.GRANT && trace.accessEffect() == RuleEffect.ALLOW) {
                hasExplicitGrantAllow = true;
            }
        }
        if (hasRestrictDeny) {
            return EnforcementDisposition.DENY;
        }

        if (pointAuthorityMode == PointAuthorityMode.RESTRICT_BASELINE) {
            // In RESTRICT_BASELINE, dynamic policies can only restrict the structural baseline; never expand it.
            return structuralBaselineAllowed ? EnforcementDisposition.PERMIT : EnforcementDisposition.DENY;
        }

        // In AUTHORITATIVE_EXECUTION + PointAuthorityMode.AUTHORITATIVE, at least one explicit GRANT ALLOW
        // and GateOutcome.ALLOW are required (Default-Deny when NOT_APPLICABLE).
        return (canGrantAccessBeyondBaseline() && envelope.gateOutcome() == GateOutcome.ALLOW && hasExplicitGrantAllow)
                ? EnforcementDisposition.PERMIT
                : EnforcementDisposition.DENY;
    }
}
