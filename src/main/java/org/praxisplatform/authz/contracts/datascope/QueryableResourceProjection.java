package org.praxisplatform.authz.contracts.datascope;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Persistence-neutral projection of queryable resource fields against which {@link SearchPredicateIr}
 * and {@code authorization-search-source/v1} conditions are validated ({@code CC03}, {@code DSP-FLD-001..007}).
 *
 * @param schemaVersion canonical schema version ({@link #SCHEMA_VERSION_V1})
 * @param projectionId unique projection identifier
 * @param resourceKey canonical resource key
 * @param projectionDigest SHA-256 digest of this projection
 * @param fieldsByPath map of {@code fieldPath -> QueryableFieldDescriptor}
 */
public record QueryableResourceProjection(
        String schemaVersion,
        String projectionId,
        String resourceKey,
        String projectionDigest,
        Map<String, QueryableFieldDescriptor> fieldsByPath
) {

    /** Canonical schema version for {@link QueryableResourceProjection}. */
    public static final String SCHEMA_VERSION_V1 = "praxis.queryable-resource-projection/v1";

    /** Validates schema version, digest, and field key alignment. */
    public QueryableResourceProjection {
        schemaVersion = requireNonBlank(schemaVersion, "schemaVersion");
        if (!SCHEMA_VERSION_V1.equals(schemaVersion)) {
            throw new IllegalArgumentException("Unsupported QueryableResourceProjection schemaVersion: " + schemaVersion);
        }
        projectionId = requireNonBlank(projectionId, "projectionId");
        resourceKey = requireNonBlank(resourceKey, "resourceKey");
        projectionDigest = requireNonBlank(projectionDigest, "projectionDigest");
        Objects.requireNonNull(fieldsByPath, "fieldsByPath is required");
        if (fieldsByPath.isEmpty()) {
            throw new IllegalArgumentException("fieldsByPath must not be empty");
        }
        for (Map.Entry<String, QueryableFieldDescriptor> entry : fieldsByPath.entrySet()) {
            if (!entry.getKey().equals(entry.getValue().fieldPath())) {
                throw new IllegalArgumentException(
                        "Map key '" + entry.getKey() + "' does not match QueryableFieldDescriptor.fieldPath '"
                                + entry.getValue().fieldPath() + "'");
            }
        }
        fieldsByPath = Map.copyOf(fieldsByPath);
    }

    /** Looks up a {@link QueryableFieldDescriptor} by its canonical {@code fieldPath}. */
    public Optional<QueryableFieldDescriptor> findField(String fieldPath) {
        return Optional.ofNullable(fieldsByPath.get(fieldPath));
    }

    /**
     * Validates a {@link SearchPredicateIr} tree against this projection's queryable fields,
     * checking field existence, {@code attributeId}, {@code valueType}, {@code supportedOperators},
     * and {@link FieldRefOperandIr} compatibility ({@code DSP-FLD-002..007}, {@code DSP-AST-010}).
     *
     * @param predicate predicate tree to validate
     * @throws IllegalArgumentException if any node violates the queryable projection contract
     */
    public void validatePredicateIr(SearchPredicateIr predicate) {
        Objects.requireNonNull(predicate, "predicate is required");
        if (predicate instanceof LogicalPredicateIr logical) {
            for (SearchPredicateIr child : logical.operands()) {
                validatePredicateIr(child);
            }
            return;
        }
        if (predicate instanceof NullabilityPredicateIr nullability) {
            QueryableFieldDescriptor fd = requireQueryableField(
                    nullability.fieldPath(), nullability.attributeId(), nullability.operator());
            if (!fd.supportedOperators().contains(nullability.operator())) {
                throw new IllegalArgumentException(
                        "Operator " + nullability.operator() + " is not supported on field '" + fd.fieldPath() + "'");
            }
            return;
        }
        if (predicate instanceof ComparisonPredicateIr comp) {
            QueryableFieldDescriptor fd = requireQueryableField(
                    comp.fieldPath(), comp.attributeId(), comp.operator());
            if (fd.valueType() != comp.valueType()) {
                throw new IllegalArgumentException(
                        "ComparisonPredicateIr valueType " + comp.valueType() + " does not match field '"
                                + fd.fieldPath() + "' valueType " + fd.valueType());
            }
            if (comp.rightOperand() instanceof FieldRefOperandIr fieldRef) {
                if (!fd.allowFieldRefComparison()) {
                    throw new IllegalArgumentException(
                            "Field '" + fd.fieldPath() + "' does not allow FieldRefOperandIr comparisons (DSP-AST-010)");
                }
                QueryableFieldDescriptor rhsFd = requireQueryableField(
                        fieldRef.targetFieldPath(), fieldRef.targetAttributeId(), comp.operator());
                if (!rhsFd.allowFieldRefComparison()) {
                    throw new IllegalArgumentException(
                            "Target field '" + rhsFd.fieldPath()
                                    + "' does not allow FieldRefOperandIr comparisons (DSP-AST-010)");
                }
                if (fd.valueType() != rhsFd.valueType()) {
                    throw new IllegalArgumentException(
                            "FieldRefOperandIr type mismatch between '" + fd.fieldPath() + "' (" + fd.valueType()
                                    + ") and '" + rhsFd.fieldPath() + "' (" + rhsFd.valueType() + ") (DSP-AST-010)");
                }
            }
        }
    }

    private QueryableFieldDescriptor requireQueryableField(
            String fieldPath,
            String attributeId,
            SearchPredicateOperator operator
    ) {
        QueryableFieldDescriptor fd = fieldsByPath.get(fieldPath);
        if (fd == null) {
            throw new IllegalArgumentException(
                    "Field '" + fieldPath + "' is not declared in QueryableResourceProjection '" + projectionId + "'");
        }
        if (!fd.attributeId().equals(attributeId)) {
            throw new IllegalArgumentException(
                    "AttributeId mismatch for field '" + fieldPath + "': expected '" + fd.attributeId()
                            + "' but got '" + attributeId + "'");
        }
        if (!fd.supportedOperators().contains(operator)) {
            throw new IllegalArgumentException(
                    "Operator " + operator + " is not supported on queryable field '" + fieldPath + "'");
        }
        return fd;
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
