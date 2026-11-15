package org.praxisplatform.authz.contracts.envelope;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;

/**
 * Sanitized audit and diagnostic evidence emitted by the host PEP after normalizing a
 * {@link ProviderEvaluationEnvelope} ({@code CC07}, {@code BND-PRV-004}).
 *
 * <p>Per {@code BND-PRV-004}, this record stores only strategy identifiers, obligation types, and
 * semantic reason codes — never raw values of sensitive or restricted attributes.</p>
 *
 * @param evidenceId unique evidence identifier
 * @param decisionPointKey canonical decision point key
 * @param evaluationMode evaluation mode
 * @param runtimeRevision provider runtime revision
 * @param policySetDigest provider policy set digest
 * @param factContractDigest governing fact contract digest
 * @param gateOutcome provider gate outcome
 * @param finalDisposition final binary PEP disposition ({@code PERMIT} or {@code DENY})
 * @param reasonCodes semantic reason codes
 * @param appliedMaskStrategiesByAttributeId map of {@code attributeId -> strategyId} (never raw field values)
 * @param fulfilledObligationTypes obligation types fulfilled
 * @param unfulfilledObligationTypes obligation types that failed fulfillment
 * @param decidedAt decision timestamp
 */
public record DecisionEvidence(
        String evidenceId,
        String decisionPointKey,
        EvaluationMode evaluationMode,
        String runtimeRevision,
        String policySetDigest,
        String factContractDigest,
        GateOutcome gateOutcome,
        EnforcementDisposition finalDisposition,
        Set<String> reasonCodes,
        Map<String, String> appliedMaskStrategiesByAttributeId,
        Set<String> fulfilledObligationTypes,
        Set<String> unfulfilledObligationTypes,
        Instant decidedAt
) {

    /** Validates required fields and ensures unfulfilled obligations never coexist with {@code PERMIT}. */
    public DecisionEvidence {
        evidenceId = requireNonBlank(evidenceId, "evidenceId");
        decisionPointKey = requireNonBlank(decisionPointKey, "decisionPointKey");
        evaluationMode = Objects.requireNonNull(evaluationMode, "evaluationMode is required");
        runtimeRevision = requireNonBlank(runtimeRevision, "runtimeRevision");
        policySetDigest = requireNonBlank(policySetDigest, "policySetDigest");
        factContractDigest = requireNonBlank(factContractDigest, "factContractDigest");
        gateOutcome = Objects.requireNonNull(gateOutcome, "gateOutcome is required");
        finalDisposition = Objects.requireNonNull(finalDisposition, "finalDisposition is required");
        reasonCodes = reasonCodes == null ? Set.of() : Set.copyOf(reasonCodes);
        appliedMaskStrategiesByAttributeId = appliedMaskStrategiesByAttributeId == null
                ? Map.of()
                : Map.copyOf(appliedMaskStrategiesByAttributeId);
        fulfilledObligationTypes = fulfilledObligationTypes == null ? Set.of() : Set.copyOf(fulfilledObligationTypes);
        unfulfilledObligationTypes = unfulfilledObligationTypes == null ? Set.of() : Set.copyOf(unfulfilledObligationTypes);
        if (finalDisposition == EnforcementDisposition.PERMIT && !unfulfilledObligationTypes.isEmpty()) {
            throw new IllegalArgumentException(
                    "DecisionEvidence cannot record finalDisposition=PERMIT when unfulfilledObligationTypes is non-empty (ENF-OBL-003)");
        }
        for (String fulfilled : fulfilledObligationTypes) {
            if (unfulfilledObligationTypes.contains(fulfilled)) {
                throw new IllegalArgumentException(
                        "Obligation type '" + fulfilled + "' cannot be both fulfilled and unfulfilled in DecisionEvidence");
            }
        }
        decidedAt = Objects.requireNonNull(decidedAt, "decidedAt is required");
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
