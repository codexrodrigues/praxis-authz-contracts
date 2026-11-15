package org.praxisplatform.authz.contracts.binding;

/**
 * Transaction cardinality of a resource operation or command ({@code ENF-BAT-001..005}).
 */
public enum TransactionCardinality {
    SINGLE_ITEM,
    ITEM_INDEPENDENT,
    STATEMENT_ATOMIC
}
