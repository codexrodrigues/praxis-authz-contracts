package org.praxisplatform.authz.contracts.datascope;

import java.util.Objects;
import org.praxisplatform.authz.contracts.context.FactValueType;

/**
 * Persistence-neutral comparison predicate node in {@link SearchPredicateIr} ({@code CC03}, {@code DSP-FLD-002}).
 *
 * @param operator comparison operator ({@code EQ}, {@code NE}, {@code LT}, {@code LTE}, {@code GT}, {@code GTE}, {@code IN}, {@code NIN}, {@code TEXT_CONTAINS}, {@code STARTS_WITH}, {@code ENDS_WITH})
 * @param fieldPath canonical {@code resource.*} fact path
 * @param attributeId canonical {@code @DomainLineage.attributeId}
 * @param valueType expected field value type
 * @param rightOperand right-hand operand ({@link LiteralOperandIr}, {@link LiteralListOperandIr}, or {@link FieldRefOperandIr})
 * @param caseInsensitive whether string comparison is case-insensitive
 */
public record ComparisonPredicateIr(
        SearchPredicateOperator operator,
        String fieldPath,
        String attributeId,
        FactValueType valueType,
        RightOperandIr rightOperand,
        boolean caseInsensitive
) implements SearchPredicateIr {

    /** Validates operator, canonical fieldPath, valueType, and right-hand operand compatibility. */
    public ComparisonPredicateIr {
        operator = Objects.requireNonNull(operator, "operator is required");
        if (operator.isLogical() || operator.isNullability()) {
            throw new IllegalArgumentException("ComparisonPredicateIr does not accept logical or nullability operator: " + operator);
        }
        fieldPath = requireNonBlank(fieldPath, "fieldPath");
        if (!fieldPath.startsWith("resource.")) {
            throw new IllegalArgumentException("fieldPath must start with 'resource.': " + fieldPath);
        }
        attributeId = requireNonBlank(attributeId, "attributeId");
        valueType = Objects.requireNonNull(valueType, "valueType is required");
        if (operator.isTextOnly() && valueType != FactValueType.STRING) {
            throw new IllegalArgumentException(
                    "Operator " + operator + " requires valueType=STRING; got " + valueType + " (DSP-IR-004)");
        }
        if ((operator == SearchPredicateOperator.LT
                || operator == SearchPredicateOperator.LTE
                || operator == SearchPredicateOperator.GT
                || operator == SearchPredicateOperator.GTE)
                && valueType == FactValueType.BOOLEAN) {
            throw new IllegalArgumentException(
                    "Ordered comparison operator " + operator + " is not allowed on BOOLEAN (DSP-IR-004)");
        }
        if (caseInsensitive && valueType != FactValueType.STRING) {
            throw new IllegalArgumentException(
                    "caseInsensitive=true requires valueType=STRING; got " + valueType + " (DSP-IR-004)");
        }
        rightOperand = Objects.requireNonNull(rightOperand, "rightOperand is required");
        if ((operator == SearchPredicateOperator.IN || operator == SearchPredicateOperator.NIN)
                && !(rightOperand instanceof LiteralListOperandIr)) {
            throw new IllegalArgumentException(operator + " requires LiteralListOperandIr rightOperand");
        }
        if (operator != SearchPredicateOperator.IN && operator != SearchPredicateOperator.NIN
                && (rightOperand instanceof LiteralListOperandIr)) {
            throw new IllegalArgumentException("LiteralListOperandIr is only valid with IN or NIN");
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
