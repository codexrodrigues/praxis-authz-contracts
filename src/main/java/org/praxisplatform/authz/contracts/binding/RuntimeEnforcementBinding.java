package org.praxisplatform.authz.contracts.binding;

import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointRef;
import org.praxisplatform.authz.contracts.decisionpoint.EnforcementCapability;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.decisionpoint.PointAuthorityMode;

/**
 * Canonical binding between a {@link DecisionPointRef}, an {@link EvaluationMode}, an
 * {@link EnforcementCapability}, and a concrete host enforcement seam ({@code CC06}).
 *
 * <p>Includes all 10 elements of the frozen semantic minimum defined by
 * {@code decision-platform-architecture-baseline-v1.md} §11.</p>
 *
 * @param schemaVersion canonical schema version ({@link #SCHEMA_VERSION_V1})
 * @param bindingId unique binding identifier
 * @param decisionPointRef digest-pinned reference to the decision point
 * @param evaluationMode evaluation mode ({@code TARGET} or {@code SEARCH})
 * @param enforcementCapability bound capability ({@code ACCESS}, {@code DATA_SCOPE}, {@code FIELD_USE}, {@code FIELD_WRITE}, {@code MASK})
 * @param boundFieldUseCategories bound {@link FieldUseCategory} values when {@code enforcementCapability == FIELD_USE}
 * @param hostEnforcementPhase host enforcement phase where this binding executes
 * @param dynamicAuthoritativeProviderBinding identifier of the dynamic provider (e.g. {@code OPA_REGO_V1})
 * @param pointAuthorityMode semantic authority mode ({@code RESTRICT_BASELINE} or {@code AUTHORITATIVE})
 * @param supportedEnforcementProfile enforcement profile identifier
 * @param handlerOrQueryAdapterProfile concrete handler or query adapter profile identifier
 * @param requiredHostContractVersion required host contract version
 * @param batchAuthorizationMode batch authorization mode
 * @param transactionCardinality transaction cardinality
 * @param bindingDigest deterministic digest of the static binding contract (excluding {@code readinessEvidence})
 * @param readinessEvidence derived runtime/deployment readiness overlay
 */
public record RuntimeEnforcementBinding(
        String schemaVersion,
        String bindingId,
        DecisionPointRef decisionPointRef,
        EvaluationMode evaluationMode,
        EnforcementCapability enforcementCapability,
        Set<FieldUseCategory> boundFieldUseCategories,
        HostEnforcementPhase hostEnforcementPhase,
        String dynamicAuthoritativeProviderBinding,
        PointAuthorityMode pointAuthorityMode,
        String supportedEnforcementProfile,
        String handlerOrQueryAdapterProfile,
        String requiredHostContractVersion,
        BatchAuthorizationMode batchAuthorizationMode,
        TransactionCardinality transactionCardinality,
        String bindingDigest,
        ReadinessEvidenceOverlay readinessEvidence
) {

    /** Canonical schema version for {@link RuntimeEnforcementBinding}. */
    public static final String SCHEMA_VERSION_V1 = "praxis.runtime-enforcement-binding/v1";

    /** Validates all 10 frozen minimum fields and capability/phase coherence. */
    public RuntimeEnforcementBinding {
        schemaVersion = requireNonBlank(schemaVersion, "schemaVersion");
        if (!SCHEMA_VERSION_V1.equals(schemaVersion)) {
            throw new IllegalArgumentException("Unsupported RuntimeEnforcementBinding schemaVersion: " + schemaVersion);
        }
        bindingId = requireNonBlank(bindingId, "bindingId");
        decisionPointRef = Objects.requireNonNull(decisionPointRef, "decisionPointRef is required");
        evaluationMode = Objects.requireNonNull(evaluationMode, "evaluationMode is required");
        enforcementCapability = Objects.requireNonNull(enforcementCapability, "enforcementCapability is required");
        boundFieldUseCategories = boundFieldUseCategories == null ? Set.of() : Set.copyOf(boundFieldUseCategories);
        if (enforcementCapability == EnforcementCapability.FIELD_USE && boundFieldUseCategories.isEmpty()) {
            throw new IllegalArgumentException(
                    "RuntimeEnforcementBinding for FIELD_USE must specify boundFieldUseCategories");
        }
        if (enforcementCapability == EnforcementCapability.DATA_SCOPE && evaluationMode != EvaluationMode.SEARCH) {
            throw new IllegalArgumentException("DATA_SCOPE capability binding requires evaluationMode=SEARCH");
        }
        hostEnforcementPhase = Objects.requireNonNull(hostEnforcementPhase, "hostEnforcementPhase is required");
        dynamicAuthoritativeProviderBinding = requireNonBlank(
                dynamicAuthoritativeProviderBinding, "dynamicAuthoritativeProviderBinding");
        pointAuthorityMode = Objects.requireNonNull(pointAuthorityMode, "pointAuthorityMode is required");
        supportedEnforcementProfile = requireNonBlank(supportedEnforcementProfile, "supportedEnforcementProfile");
        handlerOrQueryAdapterProfile = requireNonBlank(handlerOrQueryAdapterProfile, "handlerOrQueryAdapterProfile");
        requiredHostContractVersion = requireNonBlank(requiredHostContractVersion, "requiredHostContractVersion");
        batchAuthorizationMode = Objects.requireNonNull(batchAuthorizationMode, "batchAuthorizationMode is required");
        transactionCardinality = Objects.requireNonNull(transactionCardinality, "transactionCardinality is required");
        bindingDigest = requireNonBlank(bindingDigest, "bindingDigest");
    }

    /** Returns {@code true} iff {@code readinessEvidence} is present and all 4 stages are verified. */
    public boolean isAuthoritativeReady() {
        return readinessEvidence != null && readinessEvidence.isAuthoritativeReady();
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
