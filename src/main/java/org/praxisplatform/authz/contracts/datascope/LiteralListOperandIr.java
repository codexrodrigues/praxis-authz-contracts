package org.praxisplatform.authz.contracts.datascope;

import java.util.List;
import java.util.Objects;

/**
 * Finite list of non-null literals for {@code IN} and {@code NIN} predicates ({@code DSP-AST-006}).
 *
 * @param values non-empty immutable list of literal values
 */
public record LiteralListOperandIr(List<Object> values) implements RightOperandIr {

    /** Validates non-empty list without null elements. */
    public LiteralListOperandIr {
        Objects.requireNonNull(values, "values is required");
        if (values.isEmpty()) {
            throw new IllegalArgumentException("LiteralListOperandIr values must not be empty");
        }
        values = List.copyOf(values);
    }
}
