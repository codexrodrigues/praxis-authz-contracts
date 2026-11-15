package org.praxisplatform.authz.contracts.datascope;

/**
 * Persistence-neutral intermediate representation of a {@code DATA_SCOPE} search predicate ({@code CC03}).
 */
public sealed interface SearchPredicateIr
        permits LogicalPredicateIr, ComparisonPredicateIr, NullabilityPredicateIr {

    /** Canonical schema version for {@link SearchPredicateIr}. */
    String SCHEMA_VERSION_V1 = "praxis.search-predicate-ir/v1";

    /** Returns the operator of this predicate node. */
    SearchPredicateOperator operator();
}
