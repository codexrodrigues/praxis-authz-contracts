package org.praxisplatform.authz.contracts.context;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Immutable runtime snapshot of resolved authorization facts for a single evaluation phase ({@code CC04}).
 *
 * @param schemaVersion canonical schema version ({@link #SCHEMA_VERSION_V1})
 * @param snapshotId unique identifier of this snapshot instance
 * @param profileId identifier of the {@link ContextCompositionProfile} used
 * @param factContractId identifier of the governing {@link FactContract}
 * @param factContractDigest canonical digest of the governing {@link FactContract}
 * @param phase evaluation phase ({@code ADMISSION} or {@code TARGET})
 * @param temporalContext authoritative server-computed temporal reference
 * @param facts resolved fact values keyed by {@code factPath}
 * @param modifiedAttributeIds set of canonical {@code attributeId}s present in the caller's write intent
 */
public record EvaluationContextSnapshot(
        String schemaVersion,
        String snapshotId,
        String profileId,
        String factContractId,
        String factContractDigest,
        ContextEvaluationPhase phase,
        TemporalContext temporalContext,
        Map<String, ResolvedFactValue> facts,
        Set<String> modifiedAttributeIds
) {

    /** Canonical schema version for {@link EvaluationContextSnapshot}. */
    public static final String SCHEMA_VERSION_V1 = "praxis.evaluation-context-snapshot/v1";

    /** Validates schema version, fact key alignment, and immutability. */
    public EvaluationContextSnapshot {
        schemaVersion = requireNonBlank(schemaVersion, "schemaVersion");
        if (!SCHEMA_VERSION_V1.equals(schemaVersion)) {
            throw new IllegalArgumentException("Unsupported EvaluationContextSnapshot schemaVersion: " + schemaVersion);
        }
        snapshotId = requireNonBlank(snapshotId, "snapshotId");
        profileId = requireNonBlank(profileId, "profileId");
        factContractId = requireNonBlank(factContractId, "factContractId");
        factContractDigest = requireNonBlank(factContractDigest, "factContractDigest");
        phase = Objects.requireNonNull(phase, "phase is required");
        temporalContext = Objects.requireNonNull(temporalContext, "temporalContext is required");
        Objects.requireNonNull(facts, "facts is required");
        for (Map.Entry<String, ResolvedFactValue> entry : facts.entrySet()) {
            if (!entry.getKey().equals(entry.getValue().factPath())) {
                throw new IllegalArgumentException(
                        "Fact map key '" + entry.getKey() + "' does not match ResolvedFactValue.factPath '"
                                + entry.getValue().factPath() + "'");
            }
        }
        facts = Map.copyOf(facts);
        modifiedAttributeIds = modifiedAttributeIds == null ? Set.of() : Set.copyOf(modifiedAttributeIds);
    }

    /** Retrieves the {@link ResolvedFactValue} for a given {@code factPath}, if present in the snapshot. */
    public Optional<ResolvedFactValue> findFact(String factPath) {
        return Optional.ofNullable(facts.get(factPath));
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
