package org.praxisplatform.authz.contracts.policy;

import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.context.FactDescriptor;

/**
 * Field selector in {@code FIELD_USE}, {@code FIELD_WRITE}, and {@code MASK} contributions
 * ({@code CC01}, {@code PDP-FLD-001..007}).
 *
 * <p>When {@code kind == GOVERNANCE}, all classification, dataCategory, and legalPurpose tokens are
 * validated against the canonical {@code praxis-metadata-starter} vocabulary.</p>
 *
 * @param kind selector kind ({@code EXACT}, {@code GOVERNANCE}, {@code LINEAGE}, {@code CONCEPT})
 * @param attributeIds exact canonical {@code attributeId}s when {@code kind == EXACT}
 * @param classifications matched {@code DomainClassification} names when {@code kind == GOVERNANCE}
 * @param dataCategories matched {@code DomainDataCategory} names when {@code kind == GOVERNANCE}
 * @param complianceTags matched compliance tags when {@code kind == GOVERNANCE}
 * @param legalPurposes matched {@code LegalTreatmentPurpose} names when {@code kind == GOVERNANCE}
 * @param lineageDomainOwner matched domain owner when {@code kind == LINEAGE}
 * @param lineageAttributePrefix matched attributeId prefix when {@code kind == LINEAGE}
 * @param semanticConceptKey matched semantic concept key when {@code kind == CONCEPT}
 */
public record PolicyFieldSelector(
        FieldSelectorKind kind,
        Set<String> attributeIds,
        Set<String> classifications,
        Set<String> dataCategories,
        Set<String> complianceTags,
        Set<String> legalPurposes,
        String lineageDomainOwner,
        String lineageAttributePrefix,
        String semanticConceptKey
) {

    /** Validates selector criteria and canonical governance vocabulary ({@code PDP-FLD-003}). */
    public PolicyFieldSelector {
        kind = Objects.requireNonNull(kind, "kind is required");
        attributeIds = attributeIds == null ? Set.of() : Set.copyOf(attributeIds);
        classifications = classifications == null ? Set.of() : Set.copyOf(classifications);
        dataCategories = dataCategories == null ? Set.of() : Set.copyOf(dataCategories);
        complianceTags = complianceTags == null ? Set.of() : Set.copyOf(complianceTags);
        legalPurposes = legalPurposes == null ? Set.of() : Set.copyOf(legalPurposes);

        for (String cls : classifications) {
            if (!FactDescriptor.ALLOWED_CLASSIFICATIONS.contains(cls)) {
                throw new IllegalArgumentException(
                        "Unsupported governance classification '" + cls + "' in PolicyFieldSelector (PDP-FLD-003)");
            }
        }
        for (String cat : dataCategories) {
            if (!FactDescriptor.ALLOWED_DATA_CATEGORIES.contains(cat)) {
                throw new IllegalArgumentException(
                        "Unsupported governance dataCategory '" + cat + "' in PolicyFieldSelector (PDP-FLD-003)");
            }
        }
        for (String lp : legalPurposes) {
            if (!FactDescriptor.ALLOWED_LEGAL_PURPOSES.contains(lp)) {
                throw new IllegalArgumentException(
                        "Unsupported governance legalPurpose '" + lp + "' in PolicyFieldSelector (PDP-FLD-003)");
            }
        }

        switch (kind) {
            case EXACT -> {
                if (attributeIds.isEmpty()) {
                    throw new IllegalArgumentException("EXACT PolicyFieldSelector must specify non-empty attributeIds");
                }
            }
            case GOVERNANCE -> {
                if (classifications.isEmpty() && dataCategories.isEmpty()
                        && complianceTags.isEmpty() && legalPurposes.isEmpty()) {
                    throw new IllegalArgumentException(
                            "GOVERNANCE PolicyFieldSelector must specify at least one governance criterion");
                }
            }
            case LINEAGE -> {
                if ((lineageDomainOwner == null || lineageDomainOwner.isBlank())
                        && (lineageAttributePrefix == null || lineageAttributePrefix.isBlank())) {
                    throw new IllegalArgumentException(
                            "LINEAGE PolicyFieldSelector must specify lineageDomainOwner or lineageAttributePrefix");
                }
            }
            case CONCEPT -> {
                if (semanticConceptKey == null || semanticConceptKey.isBlank()) {
                    throw new IllegalArgumentException("CONCEPT PolicyFieldSelector must specify semanticConceptKey");
                }
            }
        }
    }

    /** Convenience factory for an {@link FieldSelectorKind#EXACT} selector. */
    public static PolicyFieldSelector exact(Set<String> attributeIds) {
        return new PolicyFieldSelector(
                FieldSelectorKind.EXACT,
                attributeIds,
                Set.of(),
                Set.of(),
                Set.of(),
                Set.of(),
                null,
                null,
                null
        );
    }

    /** Convenience factory for a {@link FieldSelectorKind#GOVERNANCE} selector. */
    public static PolicyFieldSelector governance(
            Set<String> classifications,
            Set<String> dataCategories,
            Set<String> complianceTags
    ) {
        return new PolicyFieldSelector(
                FieldSelectorKind.GOVERNANCE,
                Set.of(),
                classifications,
                dataCategories,
                complianceTags,
                Set.of(),
                null,
                null,
                null
        );
    }

    /**
     * Returns a deterministic canonical preimage with lexicographically sorted set elements,
     * suitable for SHA-256 digest calculation across JVM processes ({@code BND-DIG-001}).
     */
    public String toCanonicalPreimage() {
        return "PolicyFieldSelector[kind=" + kind
                + ",attributeIds=" + attributeIds.stream().sorted().toList()
                + ",classifications=" + classifications.stream().sorted().toList()
                + ",dataCategories=" + dataCategories.stream().sorted().toList()
                + ",complianceTags=" + complianceTags.stream().sorted().toList()
                + ",legalPurposes=" + legalPurposes.stream().sorted().toList()
                + ",lineageDomainOwner=" + (lineageDomainOwner == null ? "" : lineageDomainOwner)
                + ",lineageAttributePrefix=" + (lineageAttributePrefix == null ? "" : lineageAttributePrefix)
                + ",semanticConceptKey=" + (semanticConceptKey == null ? "" : semanticConceptKey)
                + "]";
    }
}
