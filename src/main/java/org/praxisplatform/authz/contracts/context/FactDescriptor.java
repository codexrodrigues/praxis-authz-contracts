package org.praxisplatform.authz.contracts.context;

import java.util.Objects;
import java.util.Set;

/**
 * Persistence-neutral descriptor of a single fact inside a {@link FactContract} ({@code CC04}).
 *
 * <p>Governance attributes align 1:1 with the canonical enums in {@code praxis-metadata-starter}:
 * {@code DomainClassification} ({@code PUBLIC}, {@code INTERNAL}, {@code CONFIDENTIAL}, {@code RESTRICTED}),
 * {@code DomainDataCategory} ({@code CREDENTIAL}, {@code SENSITIVE_PERSONAL}, {@code PERSONAL},
 * {@code FINANCIAL}, {@code OPERATIONAL}, {@code LEGAL}), and {@code LegalTreatmentPurpose}.</p>
 *
 * @param factPath canonical SARC path (e.g. {@code subject.organizationUnitIds}, {@code resource.cidCodigo})
 * @param namespace SARC namespace matching the prefix of {@code factPath}
 * @param valueType canonical scalar or element value type
 * @param cardinality scalar, set, or list cardinality
 * @param presenceModel structural presence model ({@code ALWAYS_PRESENT} or {@code MAY_BE_ABSENT})
 * @param attributeId optional canonical {@code @DomainLineage.attributeId}
 * @param resourceFactId optional canonical {@code @ResourceFact} identifier
 * @param resolutionStage stage in which the fact is resolved
 * @param availableInPhases evaluation phases in which the fact is available
 * @param searchQueryable whether the fact is eligible for {@code SEARCH} predicate pushdown
 * @param classification optional {@code DomainClassification} name
 * @param dataCategory optional {@code DomainDataCategory} name
 * @param complianceTags immutable set of compliance tags (e.g. {@code HEALTH_DATA})
 * @param legalPurpose optional {@code LegalTreatmentPurpose} name
 * @param freshnessPolicy optional freshness policy for enriched/cached facts
 */
public record FactDescriptor(
        String factPath,
        FactSlotNamespace namespace,
        FactValueType valueType,
        FactCardinality cardinality,
        FactPresenceModel presenceModel,
        String attributeId,
        String resourceFactId,
        FactResolutionStage resolutionStage,
        Set<ContextEvaluationPhase> availableInPhases,
        boolean searchQueryable,
        String classification,
        String dataCategory,
        Set<String> complianceTags,
        String legalPurpose,
        FactFreshnessPolicy freshnessPolicy
) {

    /** Canonical {@code DomainClassification} names from {@code praxis-metadata-starter}. */
    public static final Set<String> ALLOWED_CLASSIFICATIONS = Set.of(
            "PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"
    );

    /** Canonical {@code DomainDataCategory} names from {@code praxis-metadata-starter}. */
    public static final Set<String> ALLOWED_DATA_CATEGORIES = Set.of(
            "CREDENTIAL", "SENSITIVE_PERSONAL", "PERSONAL", "FINANCIAL", "OPERATIONAL", "LEGAL"
    );

    /** Canonical {@code LegalTreatmentPurpose} names from {@code praxis-metadata-starter}. */
    public static final Set<String> ALLOWED_LEGAL_PURPOSES = Set.of(
            "UNSPECIFIED",
            "HUMAN_RESOURCES_ADMINISTRATION",
            "PAYROLL_AND_TAX_COMPLIANCE",
            "OFFICIAL_HEALTH_EXPERTISE",
            "SOCIAL_SECURITY_AND_BENEFITS",
            "ACTIVE_PUBLIC_TRANSPARENCY_LAI",
            "EXTERNAL_AUDIT_CONTROL",
            "EMPLOYEE_SELF_SERVICE",
            "STATUTORY_LEGAL_OBLIGATION"
    );

    /** Validates namespace prefix, search eligibility, and canonical governance vocabulary. */
    public FactDescriptor {
        factPath = requireNonBlank(factPath, "factPath");
        namespace = Objects.requireNonNull(namespace, "namespace is required");
        if (!factPath.startsWith(namespace.prefix())) {
            throw new IllegalArgumentException(
                    "factPath '" + factPath + "' must start with namespace prefix '" + namespace.prefix() + "'");
        }
        valueType = Objects.requireNonNull(valueType, "valueType is required");
        cardinality = Objects.requireNonNull(cardinality, "cardinality is required");
        presenceModel = Objects.requireNonNull(presenceModel, "presenceModel is required");
        attributeId = normalizeOptional(attributeId);
        resourceFactId = normalizeOptional(resourceFactId);
        resolutionStage = Objects.requireNonNull(resolutionStage, "resolutionStage is required");
        Objects.requireNonNull(availableInPhases, "availableInPhases is required");
        if (availableInPhases.isEmpty()) {
            throw new IllegalArgumentException("availableInPhases must not be empty");
        }
        availableInPhases = Set.copyOf(availableInPhases);
        if (searchQueryable && namespace != FactSlotNamespace.RESOURCE) {
            throw new IllegalArgumentException("Only RESOURCE facts can be marked searchQueryable=true");
        }
        if (searchQueryable && resolutionStage == FactResolutionStage.DERIVE) {
            throw new IllegalArgumentException("DERIVE stage facts cannot be marked searchQueryable=true");
        }
        classification = normalizeOptional(classification);
        if (classification != null && !ALLOWED_CLASSIFICATIONS.contains(classification)) {
            throw new IllegalArgumentException(
                    "Unsupported classification '" + classification + "'; must be one of " + ALLOWED_CLASSIFICATIONS);
        }
        dataCategory = normalizeOptional(dataCategory);
        if (dataCategory != null && !ALLOWED_DATA_CATEGORIES.contains(dataCategory)) {
            throw new IllegalArgumentException(
                    "Unsupported dataCategory '" + dataCategory + "'; must be one of " + ALLOWED_DATA_CATEGORIES);
        }
        complianceTags = complianceTags == null ? Set.of() : Set.copyOf(complianceTags);
        legalPurpose = normalizeOptional(legalPurpose);
        if (legalPurpose != null && !ALLOWED_LEGAL_PURPOSES.contains(legalPurpose)) {
            throw new IllegalArgumentException(
                    "Unsupported legalPurpose '" + legalPurpose + "'; must be one of " + ALLOWED_LEGAL_PURPOSES);
        }
    }

    /** Returns {@code true} when this fact carries sensitive or restricted governance classification. */
    public boolean isSensitiveOrRestricted() {
        return "RESTRICTED".equals(classification)
                || "CONFIDENTIAL".equals(classification)
                || "SENSITIVE_PERSONAL".equals(dataCategory)
                || "CREDENTIAL".equals(dataCategory)
                || !complianceTags.isEmpty();
    }

    private static String requireNonBlank(String value, String field) {
        Objects.requireNonNull(value, field + " is required");
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return trimmed;
    }

    private static String normalizeOptional(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
