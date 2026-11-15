package org.praxisplatform.authz.contracts.datascope;

import java.util.Objects;

/**
 * Persistence-neutral unary nullability predicate ({@code IS_NULL} or {@code IS_NOT_NULL}) in {@link SearchPredicateIr}.
 *
 * @param operator {@link SearchPredicateOperator#IS_NULL} or {@link SearchPredicateOperator#IS_NOT_NULL}
 * @param fieldPath canonical {@code resource.*} fact path
 * @param attributeId canonical {@code @DomainLineage.attributeId}
 */
public record NullabilityPredicateIr(
        SearchPredicateOperator operator,
        String fieldPath,
        String attributeId
) implements SearchPredicateIr {

    /** Validates nullability operator and canonical resource field path. */
    public NullabilityPredicateIr {
        operator = Objects.requireNonNull(operator, "operator is required");
        if (!operator.isNullability()) {
            throw new IllegalArgumentException("NullabilityPredicateIr requires IS_NULL or IS_NOT_NULL; got " + operator);
        }
        Objects.requireNonNull(fieldPath, "fieldPath is required");
        fieldPath = fieldPath.trim();
        if (!fieldPath.startsWith("resource.")) {
            throw new IllegalArgumentException("fieldPath must start with 'resource.': " + fieldPath);
        }
        Objects.requireNonNull(attributeId, "attributeId is required");
        attributeId = attributeId.trim();
        if (attributeId.isEmpty()) {
            throw new IllegalArgumentException("attributeId must not be blank");
        }
    }
}
