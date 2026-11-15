package org.praxisplatform.authz.contracts.datascope;

import java.util.Objects;

/**
 * Non-null scalar literal right-hand operand in a {@link ComparisonPredicateIr}.
 *
 * @param value scalar literal value (must not be null; use {@link NullabilityPredicateIr} for null checks)
 */
public record LiteralOperandIr(Object value) implements RightOperandIr {

    /** Validates non-null scalar literal. */
    public LiteralOperandIr {
        value = Objects.requireNonNull(value, "LiteralOperandIr value must not be null; use IS_NULL/IS_NOT_NULL for null checks");
    }
}
