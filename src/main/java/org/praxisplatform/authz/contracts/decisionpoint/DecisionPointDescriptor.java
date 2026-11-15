package org.praxisplatform.authz.contracts.decisionpoint;

import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.context.FactDescriptor;

/**
 * Canonical static descriptor of an authorization or business decision point ({@code CC05}, {@code DPC-*}).
 *
 * <p>Per {@code DPC-GEN-002A}, {@link PointAuthorityMode} does not belong to this static descriptor;
 * it is bound on {@link org.praxisplatform.authz.contracts.binding.RuntimeEnforcementBinding}.</p>
 *
 * @param schemaVersion canonical schema version ({@link #SCHEMA_VERSION_V1})
 * @param identity canonical structured identity and serialized {@code pointKey}
 * @param decisionKind {@code AUTHORIZATION} or {@code BUSINESS}
 * @param resultContract {@code GATE} or {@code VALUE}
 * @param intentId optional {@code @ResourceIntent} identifier
 * @param operationVerb semantic operation verb (e.g. {@code READ}, {@code SEARCH}, {@code UPDATE_PARTIAL})
 * @param httpMethod optional HTTP method
 * @param canonicalPath optional canonical HTTP path
 * @param evaluationModes supported evaluation modes ({@code TARGET}, {@code SEARCH})
 * @param supportedCapabilities supported enforcement capabilities
 * @param supportedFieldUseCategories supported {@link FieldUseCategory} values when {@code FIELD_USE} is supported
 * @param obligationSupport obligation support profile
 * @param factContractRef reference to the governing {@code FactContract}
 * @param queryProjectionRef reference to the {@code QueryableResourceProjection} (required when {@code SEARCH} is supported)
 * @param requestSchemaRef optional request DTO schema reference
 * @param responseSchemaRef optional response DTO schema reference
 * @param legalPurpose canonical {@code LegalTreatmentPurpose} name
 * @param legalBasisRef legal basis reference
 * @param provenance provenance metadata
 * @param descriptorDigest SHA-256 digest of this descriptor
 */
public record DecisionPointDescriptor(
        String schemaVersion,
        DecisionPointIdentity identity,
        DecisionKind decisionKind,
        DecisionResultContractKind resultContract,
        String intentId,
        String operationVerb,
        String httpMethod,
        String canonicalPath,
        Set<EvaluationMode> evaluationModes,
        Set<EnforcementCapability> supportedCapabilities,
        Set<FieldUseCategory> supportedFieldUseCategories,
        ObligationSupportProfile obligationSupport,
        FactContractRef factContractRef,
        QueryableProjectionRef queryProjectionRef,
        SchemaDigestRef requestSchemaRef,
        SchemaDigestRef responseSchemaRef,
        String legalPurpose,
        String legalBasisRef,
        DecisionPointProvenance provenance,
        String descriptorDigest
) {

    /** Canonical schema version for {@link DecisionPointDescriptor}. */
    public static final String SCHEMA_VERSION_V1 = "praxis.decision-point/v1";

    /** Validates structural, capability, and mode invariants ({@code DPC-*}). */
    public DecisionPointDescriptor {
        schemaVersion = requireNonBlank(schemaVersion, "schemaVersion");
        if (!SCHEMA_VERSION_V1.equals(schemaVersion)) {
            throw new IllegalArgumentException("Unsupported DecisionPointDescriptor schemaVersion: " + schemaVersion);
        }
        identity = Objects.requireNonNull(identity, "identity is required");
        decisionKind = Objects.requireNonNull(decisionKind, "decisionKind is required");
        resultContract = Objects.requireNonNull(resultContract, "resultContract is required");
        if (decisionKind == DecisionKind.AUTHORIZATION && resultContract != DecisionResultContractKind.GATE) {
            throw new IllegalArgumentException("AUTHORIZATION decision points must declare resultContract=GATE");
        }
        operationVerb = requireNonBlank(operationVerb, "operationVerb");
        Objects.requireNonNull(evaluationModes, "evaluationModes is required");
        if (evaluationModes.isEmpty()) {
            throw new IllegalArgumentException("evaluationModes must not be empty");
        }
        evaluationModes = Set.copyOf(evaluationModes);
        Objects.requireNonNull(supportedCapabilities, "supportedCapabilities is required");
        if (supportedCapabilities.isEmpty()) {
            throw new IllegalArgumentException("supportedCapabilities must not be empty");
        }
        supportedCapabilities = Set.copyOf(supportedCapabilities);
        supportedFieldUseCategories = supportedFieldUseCategories == null
                ? Set.of()
                : Set.copyOf(supportedFieldUseCategories);
        if (supportedCapabilities.contains(EnforcementCapability.FIELD_USE) && supportedFieldUseCategories.isEmpty()) {
            throw new IllegalArgumentException(
                    "DecisionPointDescriptor supporting FIELD_USE must declare supportedFieldUseCategories");
        }
        obligationSupport = obligationSupport == null
                ? new ObligationSupportProfile(Set.of(), Set.of())
                : obligationSupport;
        factContractRef = Objects.requireNonNull(factContractRef, "factContractRef is required");
        if (evaluationModes.contains(EvaluationMode.SEARCH)) {
            if (queryProjectionRef == null) {
                throw new IllegalArgumentException(
                        "DecisionPointDescriptor supporting SEARCH mode must declare queryProjectionRef (DPC-CAP-002)");
            }
            if (!supportedCapabilities.contains(EnforcementCapability.DATA_SCOPE)
                    && !supportedCapabilities.contains(EnforcementCapability.FIELD_USE)) {
                throw new IllegalArgumentException(
                        "DecisionPointDescriptor supporting SEARCH mode must support DATA_SCOPE or FIELD_USE (DPC-CAP-002)");
            }
        }
        legalPurpose = requireNonBlank(legalPurpose, "legalPurpose");
        if (!FactDescriptor.ALLOWED_LEGAL_PURPOSES.contains(legalPurpose)) {
            throw new IllegalArgumentException(
                    "Unsupported legalPurpose '" + legalPurpose + "'; must be one of " + FactDescriptor.ALLOWED_LEGAL_PURPOSES);
        }
        provenance = provenance == null ? new DecisionPointProvenance(Set.of(), Set.of()) : provenance;
        descriptorDigest = requireNonBlank(descriptorDigest, "descriptorDigest");
    }

    /** Creates a digest-pinned {@link DecisionPointRef} pointing to this descriptor. */
    public DecisionPointRef toRef() {
        return new DecisionPointRef(
                identity.pointKey(),
                identity.pointKind(),
                identity.serviceKey(),
                identity.resourceKey(),
                identity.operationOrActionKey(),
                descriptorDigest
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
