package org.praxisplatform.authz.contracts.obligation;

/**
 * Canonical fulfillment barrier for verifiable authorization obligations ({@code CC10}, {@code ENF-OBL-001..009}).
 */
public enum ObligationFulfillmentBarrier {
    BEFORE_EXECUTION,
    BEFORE_COMMIT_OUTBOX,
    BEFORE_DISCLOSURE
}
