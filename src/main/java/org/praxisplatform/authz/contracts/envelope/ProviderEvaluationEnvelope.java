package org.praxisplatform.authz.contracts.envelope;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;

/**
 * Structured provider evaluation envelope returned by an authorization provider such as OPA ({@code CC07}).
 *
 * @param schemaVersion canonical schema version ({@link #SCHEMA_VERSION_V1})
 * @param providerKind provider identifier (e.g. {@code OPA_REGO_V1})
 * @param providerEvaluationId unique evaluation correlation identifier
 * @param decisionPointKey canonical decision point key
 * @param evaluationMode evaluation mode ({@code TARGET} or {@code SEARCH})
 * @param combiningProfileRef combining profile reference (e.g. {@code praxis.authorization-combining/v1})
 * @param runtimeRevision active provider runtime revision
 * @param policySetDigest active policy set digest
 * @param factContractDigest governing fact contract digest
 * @param gateOutcome 5-state provider gate outcome
 * @param combinedFieldUseEffects combined field-use effect directives
 * @param combinedFieldWriteEffects combined field-write effect directives
 * @param combinedMaskDirectives combined security mask directives
 * @param combinedObligationDirectives combined obligation directives
 * @param unresolvedConflicts unresolved mask or obligation conflicts ({@code ENF-GEN-019..020})
 * @param unitContributions per-unit contribution trace for audit and lineage
 * @param evaluationIssues diagnostic issues emitted during evaluation
 * @param evaluatedAt timestamp when evaluation completed
 * @param durationMicros evaluation duration in microseconds
 */
public record ProviderEvaluationEnvelope(
        String schemaVersion,
        String providerKind,
        String providerEvaluationId,
        String decisionPointKey,
        EvaluationMode evaluationMode,
        String combiningProfileRef,
        String runtimeRevision,
        String policySetDigest,
        String factContractDigest,
        GateOutcome gateOutcome,
        List<FieldUseEffectDirective> combinedFieldUseEffects,
        List<FieldWriteEffectDirective> combinedFieldWriteEffects,
        List<MaskDirective> combinedMaskDirectives,
        List<ObligationDirective> combinedObligationDirectives,
        List<PolicyConflictIssue> unresolvedConflicts,
        List<PolicyUnitContributionTrace> unitContributions,
        List<EvaluationIssue> evaluationIssues,
        Instant evaluatedAt,
        long durationMicros
) {

    /** Canonical schema version for {@link ProviderEvaluationEnvelope}. */
    public static final String SCHEMA_VERSION_V1 = "praxis.provider-evaluation-envelope/v1";

    /** Canonical issue code when OPA returns HTTP 200 without a valid versioned result document ({@code OPA-RT-004}). */
    public static final String OPA_UNDEFINED_DECISION_DOCUMENT = "OPA_UNDEFINED_DECISION_DOCUMENT";

    /** Validates schema version, required provenance identifiers, and list immutability. */
    public ProviderEvaluationEnvelope {
        schemaVersion = requireNonBlank(schemaVersion, "schemaVersion");
        if (!SCHEMA_VERSION_V1.equals(schemaVersion)) {
            throw new IllegalArgumentException("Unsupported ProviderEvaluationEnvelope schemaVersion: " + schemaVersion);
        }
        providerKind = requireNonBlank(providerKind, "providerKind");
        providerEvaluationId = requireNonBlank(providerEvaluationId, "providerEvaluationId");
        decisionPointKey = requireNonBlank(decisionPointKey, "decisionPointKey");
        evaluationMode = Objects.requireNonNull(evaluationMode, "evaluationMode is required");
        combiningProfileRef = requireNonBlank(combiningProfileRef, "combiningProfileRef");
        runtimeRevision = requireNonBlank(runtimeRevision, "runtimeRevision");
        policySetDigest = requireNonBlank(policySetDigest, "policySetDigest");
        factContractDigest = requireNonBlank(factContractDigest, "factContractDigest");
        gateOutcome = Objects.requireNonNull(gateOutcome, "gateOutcome is required");
        combinedFieldUseEffects = combinedFieldUseEffects == null ? List.of() : List.copyOf(combinedFieldUseEffects);
        combinedFieldWriteEffects = combinedFieldWriteEffects == null ? List.of() : List.copyOf(combinedFieldWriteEffects);
        combinedMaskDirectives = combinedMaskDirectives == null ? List.of() : List.copyOf(combinedMaskDirectives);
        combinedObligationDirectives = combinedObligationDirectives == null ? List.of() : List.copyOf(combinedObligationDirectives);
        unresolvedConflicts = unresolvedConflicts == null ? List.of() : List.copyOf(unresolvedConflicts);
        unitContributions = unitContributions == null ? List.of() : List.copyOf(unitContributions);
        evaluationIssues = evaluationIssues == null ? List.of() : List.copyOf(evaluationIssues);
        evaluatedAt = Objects.requireNonNull(evaluatedAt, "evaluatedAt is required");
        if (durationMicros < 0) {
            throw new IllegalArgumentException("durationMicros must be non-negative");
        }
    }

    /**
     * Checks whether a raw decoded OPA HTTP 200 JSON map contains a well-formed {@code result}
     * map with non-blank {@code schemaVersion}, {@code runtimeRevision}, {@code policySetDigest}, and
     * {@code gateOutcome} ({@code OPA-RT-004}).
     *
     * @param rawOpaResponse raw decoded JSON map from OPA HTTP 200 response
     * @return {@code true} iff {@code result} is a non-empty map containing all required provenance keys
     */
    public static boolean isWellFormedOpaResultDocument(Map<String, Object> rawOpaResponse) {
        if (rawOpaResponse == null || !(rawOpaResponse.get("result") instanceof Map<?, ?> resultMap)) {
            return false;
        }
        return hasNonBlankString(resultMap, "schemaVersion")
                && hasNonBlankString(resultMap, "runtimeRevision")
                && hasNonBlankString(resultMap, "policySetDigest")
                && hasNonBlankString(resultMap, "gateOutcome");
    }

    private static boolean hasNonBlankString(Map<?, ?> map, String key) {
        Object val = map.get(key);
        return val instanceof String s && !s.trim().isEmpty();
    }

    /**
     * Enforces {@code OPA-RT-004}: validates a raw OPA response payload map and returns a fail-closed
     * {@link GateOutcome#TECHNICAL_ERROR} envelope whenever {@code result} is missing, empty, or lacks
     * {@code schemaVersion} / {@code runtimeRevision}.
     *
     * @param rawOpaResponse raw decoded JSON map from OPA HTTP 200 response
     * @param decisionPointKey canonical decision point key
     * @param evaluationMode evaluation mode
     * @param expectedFactContractDigest expected fact contract digest
     * @param evaluatedAt evaluation timestamp
     * @return fail-closed technical error envelope when undefined/malformed
     */
    public static ProviderEvaluationEnvelope failClosedForUndefinedOpaResult(
            Map<String, Object> rawOpaResponse,
            String decisionPointKey,
            EvaluationMode evaluationMode,
            String expectedFactContractDigest,
            Instant evaluatedAt
    ) {
        String detail = (rawOpaResponse == null || !rawOpaResponse.containsKey("result"))
                ? "OPA response omitted 'result' key (undefined Rego decision document)"
                : "OPA 'result' document is empty or missing required schemaVersion/runtimeRevision";
        return new ProviderEvaluationEnvelope(
                SCHEMA_VERSION_V1,
                "OPA_REGO_V1",
                "eval-undefined-fail-closed",
                decisionPointKey,
                evaluationMode,
                "praxis.authorization-combining/v1",
                "UNKNOWN_REVISION",
                "UNKNOWN_POLICY_SET_DIGEST",
                expectedFactContractDigest,
                GateOutcome.TECHNICAL_ERROR,
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(new EvaluationIssue(OPA_UNDEFINED_DECISION_DOCUMENT, "ERROR", null, detail)),
                evaluatedAt,
                0L
        );
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
