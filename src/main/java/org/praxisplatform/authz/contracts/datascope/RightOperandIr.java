package org.praxisplatform.authz.contracts.datascope;

/**
 * Sealed right-hand operand of a {@link ComparisonPredicateIr} ({@code DSP-AST-010}).
 */
public sealed interface RightOperandIr
        permits LiteralOperandIr, LiteralListOperandIr, FieldRefOperandIr {
}
