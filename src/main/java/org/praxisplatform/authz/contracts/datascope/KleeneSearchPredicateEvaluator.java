package org.praxisplatform.authz.contracts.datascope;

import java.math.BigDecimal;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.context.ResolvedFactValue;

/**
 * Reference Kleene 3-valued logic evaluator for {@link SearchPredicateIr} over a map of
 * {@link ResolvedFactValue}s ({@code CC03}, {@code DSP-TYPE-001..007}).
 *
 * <p>Implements the exact normative truth tables of {@code data-scope-query-plan-spec-r2.md} §31:
 * <ul>
 *   <li>Any binary comparison where either operand is {@code NULL} or {@code ABSENT}/{@code MISSING}
 *       evaluates to {@link KleeneTruthValue#UNKNOWN};</li>
 *   <li>{@code IS_NULL(PRESENT(x)) = FALSE}, {@code IS_NULL(NULL) = TRUE},
 *       {@code IS_NULL(ABSENT/MISSING) = UNKNOWN};</li>
 *   <li>{@code IS_NOT_NULL(PRESENT(x)) = TRUE}, {@code IS_NOT_NULL(NULL) = FALSE},
 *       {@code IS_NOT_NULL(ABSENT/MISSING) = UNKNOWN};</li>
 *   <li>{@code NOT(UNKNOWN) = UNKNOWN}, ensuring neither {@code IS_NULL} nor {@code NOT(IS_NULL)}
 *       ever selects a record with a structurally missing/absent attribute.</li>
 * </ul>
 */
public final class KleeneSearchPredicateEvaluator {

    private KleeneSearchPredicateEvaluator() {}

    /**
     * Evaluates a {@link SearchPredicateIr} against the provided resource fact map under Kleene 3VL.
     *
     * @param predicate predicate tree
     * @param resourceFacts map of {@code fieldPath -> ResolvedFactValue}
     * @return three-valued {@link KleeneTruthValue}
     */
    public static KleeneTruthValue evaluate(
            SearchPredicateIr predicate,
            Map<String, ResolvedFactValue> resourceFacts
    ) {
        Objects.requireNonNull(predicate, "predicate is required");
        Objects.requireNonNull(resourceFacts, "resourceFacts is required");

        if (predicate instanceof LogicalPredicateIr logical) {
            return evaluateLogical(logical, resourceFacts);
        }
        if (predicate instanceof NullabilityPredicateIr nullability) {
            return evaluateNullability(nullability, resourceFacts);
        }
        if (predicate instanceof ComparisonPredicateIr comparison) {
            return evaluateComparison(comparison, resourceFacts);
        }
        throw new IllegalArgumentException("Unsupported SearchPredicateIr type: " + predicate.getClass());
    }

    private static KleeneTruthValue evaluateLogical(
            LogicalPredicateIr logical,
            Map<String, ResolvedFactValue> resourceFacts
    ) {
        return switch (logical.operator()) {
            case NOT -> evaluate(logical.operands().get(0), resourceFacts).not();
            case AND -> {
                KleeneTruthValue acc = KleeneTruthValue.TRUE;
                for (SearchPredicateIr child : logical.operands()) {
                    acc = acc.and(evaluate(child, resourceFacts));
                    if (acc == KleeneTruthValue.FALSE) {
                        break;
                    }
                }
                yield acc;
            }
            case OR -> {
                KleeneTruthValue acc = KleeneTruthValue.FALSE;
                for (SearchPredicateIr child : logical.operands()) {
                    acc = acc.or(evaluate(child, resourceFacts));
                    if (acc == KleeneTruthValue.TRUE) {
                        break;
                    }
                }
                yield acc;
            }
            default -> throw new IllegalStateException("Unexpected logical operator: " + logical.operator());
        };
    }

    private static KleeneTruthValue evaluateNullability(
            NullabilityPredicateIr nullability,
            Map<String, ResolvedFactValue> resourceFacts
    ) {
        ResolvedFactValue resolved = resourceFacts.get(nullability.fieldPath());
        if (resolved == null || resolved.status() != FactResolutionStatus.PRESENT && resolved.status() != FactResolutionStatus.NULL) {
            // Structurally ABSENT / MISSING / STALE / UNAVAILABLE / ERROR -> UNKNOWN (DSP-TYPE-005..007)
            return KleeneTruthValue.UNKNOWN;
        }
        if (nullability.operator() == SearchPredicateOperator.IS_NULL) {
            return resolved.status() == FactResolutionStatus.NULL
                    ? KleeneTruthValue.TRUE
                    : KleeneTruthValue.FALSE;
        }
        return resolved.status() == FactResolutionStatus.PRESENT
                ? KleeneTruthValue.TRUE
                : KleeneTruthValue.FALSE;
    }

    private static KleeneTruthValue evaluateComparison(
            ComparisonPredicateIr comparison,
            Map<String, ResolvedFactValue> resourceFacts
    ) {
        ResolvedFactValue leftFact = resourceFacts.get(comparison.fieldPath());
        if (leftFact == null || leftFact.status() != FactResolutionStatus.PRESENT) {
            return KleeneTruthValue.UNKNOWN;
        }
        Object leftVal = leftFact.value();
        RightOperandIr right = comparison.rightOperand();

        if (right instanceof LiteralListOperandIr listOperand) {
            return evaluateInList(comparison.operator(), leftVal, listOperand.values(), comparison.caseInsensitive());
        }

        Object rightVal;
        if (right instanceof LiteralOperandIr literal) {
            rightVal = literal.value();
        } else if (right instanceof FieldRefOperandIr fieldRef) {
            ResolvedFactValue rightFact = resourceFacts.get(fieldRef.targetFieldPath());
            if (rightFact == null || rightFact.status() != FactResolutionStatus.PRESENT) {
                return KleeneTruthValue.UNKNOWN;
            }
            rightVal = rightFact.value();
        } else {
            return KleeneTruthValue.UNKNOWN;
        }

        return compareScalars(comparison.operator(), leftVal, rightVal, comparison.caseInsensitive());
    }

    private static KleeneTruthValue evaluateInList(
            SearchPredicateOperator op,
            Object leftVal,
            List<Object> candidates,
            boolean caseInsensitive
    ) {
        boolean matched = false;
        boolean anyUnknownType = false;
        for (Object candidate : candidates) {
            KleeneTruthValue eq = evaluateScalarEquality(leftVal, candidate, caseInsensitive);
            if (eq == KleeneTruthValue.TRUE) {
                matched = true;
                break;
            }
            if (eq == KleeneTruthValue.UNKNOWN) {
                anyUnknownType = true;
            }
        }
        if (op == SearchPredicateOperator.IN) {
            if (matched) {
                return KleeneTruthValue.TRUE;
            }
            return anyUnknownType ? KleeneTruthValue.UNKNOWN : KleeneTruthValue.FALSE;
        }
        if (matched) {
            return KleeneTruthValue.FALSE;
        }
        return anyUnknownType ? KleeneTruthValue.UNKNOWN : KleeneTruthValue.TRUE;
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static KleeneTruthValue compareScalars(
            SearchPredicateOperator op,
            Object leftVal,
            Object rightVal,
            boolean caseInsensitive
    ) {
        return switch (op) {
            case EQ -> evaluateScalarEquality(leftVal, rightVal, caseInsensitive);
            case NE -> evaluateScalarEquality(leftVal, rightVal, caseInsensitive).not();
            case LT, LTE, GT, GTE -> {
                int cmp;
                if (leftVal instanceof Number leftNum && rightVal instanceof Number rightNum) {
                    cmp = new BigDecimal(leftNum.toString()).compareTo(new BigDecimal(rightNum.toString()));
                } else if (leftVal instanceof Comparable leftCmp && leftVal.getClass().isInstance(rightVal)) {
                    cmp = leftCmp.compareTo(rightVal);
                } else {
                    yield KleeneTruthValue.UNKNOWN;
                }
                yield switch (op) {
                    case LT -> KleeneTruthValue.ofBoolean(cmp < 0);
                    case LTE -> KleeneTruthValue.ofBoolean(cmp <= 0);
                    case GT -> KleeneTruthValue.ofBoolean(cmp > 0);
                    case GTE -> KleeneTruthValue.ofBoolean(cmp >= 0);
                    default -> KleeneTruthValue.UNKNOWN;
                };
            }
            case TEXT_CONTAINS, STARTS_WITH, ENDS_WITH -> {
                if (!(leftVal instanceof String leftStr) || !(rightVal instanceof String rightStr)) {
                    yield KleeneTruthValue.UNKNOWN;
                }
                String l = caseInsensitive ? leftStr.toLowerCase(Locale.ROOT) : leftStr;
                String r = caseInsensitive ? rightStr.toLowerCase(Locale.ROOT) : rightStr;
                yield switch (op) {
                    case TEXT_CONTAINS -> KleeneTruthValue.ofBoolean(l.contains(r));
                    case STARTS_WITH -> KleeneTruthValue.ofBoolean(l.startsWith(r));
                    case ENDS_WITH -> KleeneTruthValue.ofBoolean(l.endsWith(r));
                    default -> KleeneTruthValue.UNKNOWN;
                };
            }
            default -> KleeneTruthValue.UNKNOWN;
        };
    }

    private static KleeneTruthValue evaluateScalarEquality(Object leftVal, Object rightVal, boolean caseInsensitive) {
        if (leftVal == null || rightVal == null) {
            return KleeneTruthValue.UNKNOWN;
        }
        if (leftVal instanceof Number leftNum && rightVal instanceof Number rightNum) {
            return KleeneTruthValue.ofBoolean(
                    new BigDecimal(leftNum.toString()).compareTo(new BigDecimal(rightNum.toString())) == 0);
        }
        if (leftVal instanceof String leftStr && rightVal instanceof String rightStr) {
            return KleeneTruthValue.ofBoolean(
                    caseInsensitive ? leftStr.equalsIgnoreCase(rightStr) : leftStr.equals(rightStr));
        }
        if (leftVal.getClass().equals(rightVal.getClass())) {
            return KleeneTruthValue.ofBoolean(leftVal.equals(rightVal));
        }
        return KleeneTruthValue.UNKNOWN;
    }
}
