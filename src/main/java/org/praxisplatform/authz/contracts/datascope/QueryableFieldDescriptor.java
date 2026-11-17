package org.praxisplatform.authz.contracts.datascope;

import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.context.FactValueType;

/**
 * Persistence-neutral descriptor of a single queryable resource field inside a
 * {@link QueryableResourceProjection} ({@code DSP-FLD-001..007}).
 *
 * @param fieldPath canonical resource fact path (e.g. {@code resource.departmentId})
 * @param attributeId canonical {@code @DomainLineage.attributeId}
 * @param valueType field value type
 * @param supportedOperators operators supported for pushdown on this field
 * @param allowFieldRefComparison whether this field can participate in {@link FieldRefOperandIr} comparisons
 */
public record QueryableFieldDescriptor(
        String fieldPath,
        String attributeId,
        FactValueType valueType,
        Set<SearchPredicateOperator> supportedOperators,
        boolean allowFieldRefComparison
) {

    /** Validates canonical resource path, attributeId, and operator compatibility. */
    public QueryableFieldDescriptor {
        fieldPath = requireNonBlank(fieldPath, "fieldPath");
        if (!fieldPath.startsWith("resource.")) {
            throw new IllegalArgumentException("Queryable fieldPath must start with 'resource.': " + fieldPath);
        }
        attributeId = requireNonBlank(attributeId, "attributeId");
        valueType = Objects.requireNonNull(valueType, "valueType is required");
        Objects.requireNonNull(supportedOperators, "supportedOperators is required");
        if (supportedOperators.isEmpty()) {
            throw new IllegalArgumentException("supportedOperators must not be empty");
        }
        for (SearchPredicateOperator op : supportedOperators) {
            if (op.isTextOnly() && valueType != FactValueType.STRING) {
                throw new IllegalArgumentException(
                        "Text operator " + op + " cannot be enabled on non-STRING field '" + fieldPath + "' (" + valueType + ")");
            }
        }
        supportedOperators = Set.copyOf(supportedOperators);
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
