package org.praxisplatform.authz.contracts.datascope;

/**
 * Canonical operators supported in {@link SearchPredicateIr} ({@code DSP-AST-001..010}).
 */
public enum SearchPredicateOperator {
    AND,
    OR,
    NOT,
    EQ,
    NE,
    LT,
    LTE,
    GT,
    GTE,
    IN,
    NIN,
    TEXT_CONTAINS,
    STARTS_WITH,
    ENDS_WITH,
    IS_NULL,
    IS_NOT_NULL;

    /** Returns {@code true} if this operator is a logical combinator ({@code AND}, {@code OR}, {@code NOT}). */
    public boolean isLogical() {
        return this == AND || this == OR || this == NOT;
    }

    /** Returns {@code true} if this operator is a unary nullability test ({@code IS_NULL}, {@code IS_NOT_NULL}). */
    public boolean isNullability() {
        return this == IS_NULL || this == IS_NOT_NULL;
    }

    /** Returns {@code true} if this operator requires a {@code STRING} field type. */
    public boolean isTextOnly() {
        return this == TEXT_CONTAINS || this == STARTS_WITH || this == ENDS_WITH;
    }
}
