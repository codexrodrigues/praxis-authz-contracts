package org.praxisplatform.authz.contracts.datascope;

import java.util.Objects;

/**
 * Three-valued Kleene truth value ({@code TRUE}, {@code FALSE}, {@code UNKNOWN}) governing
 * {@link SearchPredicateIr} evaluation ({@code CC03}, {@code DSP-TYPE-001..007}).
 */
public enum KleeneTruthValue {
    TRUE,
    FALSE,
    UNKNOWN;

    /** Kleene logical negation: {@code !TRUE = FALSE}, {@code !FALSE = TRUE}, {@code !UNKNOWN = UNKNOWN}. */
    public KleeneTruthValue not() {
        return switch (this) {
            case TRUE -> FALSE;
            case FALSE -> TRUE;
            case UNKNOWN -> UNKNOWN;
        };
    }

    /** Kleene logical conjunction ({@code FALSE} dominates {@code UNKNOWN}). */
    public KleeneTruthValue and(KleeneTruthValue other) {
        Objects.requireNonNull(other, "other is required");
        if (this == FALSE || other == FALSE) {
            return FALSE;
        }
        if (this == TRUE && other == TRUE) {
            return TRUE;
        }
        return UNKNOWN;
    }

    /** Kleene logical disjunction ({@code TRUE} dominates {@code UNKNOWN}). */
    public KleeneTruthValue or(KleeneTruthValue other) {
        Objects.requireNonNull(other, "other is required");
        if (this == TRUE || other == TRUE) {
            return TRUE;
        }
        if (this == FALSE && other == FALSE) {
            return FALSE;
        }
        return UNKNOWN;
    }

    /**
     * Row selection rule ({@code DSP-3VL-001}): a row belongs to the authorized scope iff the
     * predicate evaluates to {@link #TRUE}.
     */
    public boolean isRowSelected() {
        return this == TRUE;
    }

    /** Converts a standard boolean into {@link #TRUE} or {@link #FALSE}. */
    public static KleeneTruthValue ofBoolean(boolean value) {
        return value ? TRUE : FALSE;
    }
}
