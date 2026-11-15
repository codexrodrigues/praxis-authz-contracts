package org.praxisplatform.authz.contracts.context;

import java.util.Objects;
import java.util.Set;

/**
 * Context composition profile binding a decision point and phase to its required/optional facts,
 * enricher timeout, and minimization policy ({@code CC04}, {@code context-composition-spec-r3.md} §3).
 *
 * @param schemaVersion canonical schema version ({@link #SCHEMA_VERSION_V1})
 * @param profileId stable identifier of this composition profile
 * @param decisionPointKey canonical decision point key
 * @param phase evaluation phase ({@code ADMISSION} or {@code TARGET})
 * @param factContractId referenced {@link FactContract} identifier
 * @param factContractDigest expected {@link FactContract} digest
 * @param requiredFactPaths fact paths required for evaluation
 * @param optionalFactPaths fact paths optionally resolved
 * @param enricherTimeoutMillis bounded timeout in milliseconds for enrichment stage
 * @param minimizeUnreferencedSensitiveFacts whether sensitive facts not referenced by active policies are omitted
 */
public record ContextCompositionProfile(
        String schemaVersion,
        String profileId,
        String decisionPointKey,
        ContextEvaluationPhase phase,
        String factContractId,
        String factContractDigest,
        Set<String> requiredFactPaths,
        Set<String> optionalFactPaths,
        long enricherTimeoutMillis,
        boolean minimizeUnreferencedSensitiveFacts
) {

    /** Canonical schema version for {@link ContextCompositionProfile}. */
    public static final String SCHEMA_VERSION_V1 = "praxis.context-composition-profile/v1";

    /** Validates schema version, fact sets, and timeout bounds. */
    public ContextCompositionProfile {
        schemaVersion = requireNonBlank(schemaVersion, "schemaVersion");
        if (!SCHEMA_VERSION_V1.equals(schemaVersion)) {
            throw new IllegalArgumentException("Unsupported ContextCompositionProfile schemaVersion: " + schemaVersion);
        }
        profileId = requireNonBlank(profileId, "profileId");
        decisionPointKey = requireNonBlank(decisionPointKey, "decisionPointKey");
        phase = Objects.requireNonNull(phase, "phase is required");
        factContractId = requireNonBlank(factContractId, "factContractId");
        factContractDigest = requireNonBlank(factContractDigest, "factContractDigest");
        requiredFactPaths = requiredFactPaths == null ? Set.of() : Set.copyOf(requiredFactPaths);
        optionalFactPaths = optionalFactPaths == null ? Set.of() : Set.copyOf(optionalFactPaths);
        for (String reqPath : requiredFactPaths) {
            if (optionalFactPaths.contains(reqPath)) {
                throw new IllegalArgumentException(
                        "Fact path '" + reqPath + "' cannot be both required and optional in ContextCompositionProfile");
            }
        }
        if (enricherTimeoutMillis <= 0) {
            throw new IllegalArgumentException("enricherTimeoutMillis must be positive");
        }
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
