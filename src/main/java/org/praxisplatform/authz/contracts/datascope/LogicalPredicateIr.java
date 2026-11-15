package org.praxisplatform.authz.contracts.datascope;

import java.util.List;
import java.util.Objects;

/**
 * Logical combinator node ({@code AND}, {@code OR}, {@code NOT}) in {@link SearchPredicateIr}.
 *
 * @param operator logical operator
 * @param operands child predicate nodes
 */
public record LogicalPredicateIr(
        SearchPredicateOperator operator,
        List<SearchPredicateIr> operands
) implements SearchPredicateIr {

    /** Validates logical operator and arity ({@code NOT} requires 1 operand; {@code AND}/{@code OR} require at least 1). */
    public LogicalPredicateIr {
        operator = Objects.requireNonNull(operator, "operator is required");
        if (!operator.isLogical()) {
            throw new IllegalArgumentException("LogicalPredicateIr requires AND, OR, or NOT operator; got " + operator);
        }
        Objects.requireNonNull(operands, "operands is required");
        if (operands.isEmpty()) {
            throw new IllegalArgumentException("LogicalPredicateIr operands must not be empty");
        }
        if (operator == SearchPredicateOperator.NOT && operands.size() != 1) {
            throw new IllegalArgumentException("NOT operator requires exactly 1 operand; got " + operands.size());
        }
        operands = List.copyOf(operands);
    }
}
