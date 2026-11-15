package org.praxisplatform.authz.contracts.binding;

/**
 * Batch authorization failure semantics orthogonal to {@link TransactionCardinality} ({@code ENF-BAT-001..005}).
 */
public enum BatchAuthorizationMode {
    REJECT_ALL,
    PER_ITEM
}
