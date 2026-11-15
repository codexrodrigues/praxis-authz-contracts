package org.praxisplatform.authz.contracts.context;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Minimized, deterministic projection of an {@link EvaluationContextSnapshot} prepared for an external
 * authorization provider ({@code CC04}, {@code CTX-MIN-001..004}).
 *
 * @param schemaVersion canonical schema version ({@link #SCHEMA_VERSION_V1})
 * @param decisionPointKey canonical decision point key
 * @param evaluationMode evaluation mode ({@code TARGET} or {@code SEARCH})
 * @param factContractDigest digest of the governing {@link FactContract}
 * @param temporalContext authoritative temporal context
 * @param projectedInput projected map of fact values sent to the provider
 * @param projectedFactStatuses explicit status map for projected facts
 * @param omittedSensitiveFactPaths sensitive/restricted fact paths omitted by minimization policy
 */
public record ProviderInputProjection(
        String schemaVersion,
        String decisionPointKey,
        String evaluationMode,
        String factContractDigest,
        TemporalContext temporalContext,
        Map<String, Object> projectedInput,
        Map<String, FactResolutionStatus> projectedFactStatuses,
        Set<String> omittedSensitiveFactPaths
) {

    /** Canonical schema version for {@link ProviderInputProjection}. */
    public static final String SCHEMA_VERSION_V1 = "praxis.provider-input-projection/v1";

    /** Validates schema version and wraps maps/sets as unmodifiable collections. */
    public ProviderInputProjection {
        schemaVersion = requireNonBlank(schemaVersion, "schemaVersion");
        if (!SCHEMA_VERSION_V1.equals(schemaVersion)) {
            throw new IllegalArgumentException("Unsupported ProviderInputProjection schemaVersion: " + schemaVersion);
        }
        decisionPointKey = requireNonBlank(decisionPointKey, "decisionPointKey");
        evaluationMode = requireNonBlank(evaluationMode, "evaluationMode");
        if (!"TARGET".equals(evaluationMode) && !"SEARCH".equals(evaluationMode)) {
            throw new IllegalArgumentException(
                    "Unsupported evaluationMode '" + evaluationMode + "'; must be TARGET or SEARCH");
        }
        factContractDigest = requireNonBlank(factContractDigest, "factContractDigest");
        temporalContext = Objects.requireNonNull(temporalContext, "temporalContext is required");
        Objects.requireNonNull(projectedInput, "projectedInput is required");
        projectedInput = Collections.unmodifiableMap(new LinkedHashMap<>(projectedInput));
        projectedFactStatuses = projectedFactStatuses == null
                ? Map.of()
                : Collections.unmodifiableMap(new LinkedHashMap<>(projectedFactStatuses));
        omittedSensitiveFactPaths = omittedSensitiveFactPaths == null
                ? Set.of()
                : Set.copyOf(omittedSensitiveFactPaths);
    }

    /**
     * Projects an {@link EvaluationContextSnapshot} into a minimized {@link ProviderInputProjection},
     * omitting unreferenced sensitive/restricted facts when {@code profile.minimizeUnreferencedSensitiveFacts()}
     * is enabled ({@code CTX-MIN-001..004}).
     *
     * @param evaluationMode evaluation mode ({@code TARGET} or {@code SEARCH})
     * @param snapshot resolved context snapshot
     * @param contract governing fact contract
     * @param profile context composition profile
     * @param policyReferencedFactPaths fact paths explicitly referenced by active policy units
     * @return minimized provider input projection
     */
    public static ProviderInputProjection fromSnapshot(
            String evaluationMode,
            EvaluationContextSnapshot snapshot,
            FactContract contract,
            ContextCompositionProfile profile,
            Set<String> policyReferencedFactPaths
    ) {
        Objects.requireNonNull(snapshot, "snapshot is required");
        Objects.requireNonNull(contract, "contract is required");
        Objects.requireNonNull(profile, "profile is required");
        if (!snapshot.factContractId().equals(contract.factContractId())
                || !snapshot.factContractDigest().equals(contract.factContractDigest())) {
            throw new IllegalArgumentException(
                    "Snapshot factContractId/factContractDigest does not match governing FactContract (CTX-CONTRACT-002)");
        }
        if (!profile.factContractId().equals(contract.factContractId())
                || !profile.factContractDigest().equals(contract.factContractDigest())) {
            throw new IllegalArgumentException(
                    "ContextCompositionProfile factContractId/factContractDigest does not match governing FactContract (CTX-CONTRACT-002)");
        }
        Set<String> referenced = policyReferencedFactPaths == null ? Set.of() : policyReferencedFactPaths;

        Map<String, Object> projectedValues = new LinkedHashMap<>();
        Map<String, FactResolutionStatus> projectedStatuses = new LinkedHashMap<>();
        Set<String> omittedSensitive = new LinkedHashSet<>();

        for (Map.Entry<String, ResolvedFactValue> entry : snapshot.facts().entrySet()) {
            String path = entry.getKey();
            ResolvedFactValue resolved = entry.getValue();
            FactDescriptor descriptor = contract.descriptorsByPath().get(path);
            if (descriptor == null) {
                throw new IllegalArgumentException(
                        "Snapshot contains undeclared factPath '" + path + "' not present in FactContract '"
                                + contract.factContractId() + "' (CTX-BND-001)");
            }
            if ("SEARCH".equals(evaluationMode)
                    && !descriptor.availableInPhases().contains(ContextEvaluationPhase.ADMISSION)) {
                throw new IllegalArgumentException(
                        "TARGET-only fact '" + path + "' cannot be projected in SEARCH mode (CTX-PHASE-002)");
            }
            if (profile.minimizeUnreferencedSensitiveFacts()
                    && descriptor.isSensitiveOrRestricted()
                    && !referenced.contains(path)) {
                omittedSensitive.add(path);
                continue;
            }
            projectedStatuses.put(path, resolved.status());
            if (resolved.status() == FactResolutionStatus.PRESENT) {
                projectedValues.put(path, resolved.value());
            } else if (resolved.status() == FactResolutionStatus.NULL) {
                projectedValues.put(path, null);
            }
        }

        return new ProviderInputProjection(
                SCHEMA_VERSION_V1,
                profile.decisionPointKey(),
                evaluationMode,
                contract.factContractDigest(),
                snapshot.temporalContext(),
                projectedValues,
                projectedStatuses,
                omittedSensitive
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
