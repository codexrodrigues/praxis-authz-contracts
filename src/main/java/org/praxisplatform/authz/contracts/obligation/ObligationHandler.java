package org.praxisplatform.authz.contracts.obligation;

import java.util.Map;
import java.util.Set;
import org.praxisplatform.authz.contracts.envelope.ObligationDirective;

/**
 * Handler for a registered obligation type responsible for deterministic parameter merging and
 * barrier fulfillment ({@code CC10}, {@code ENF-OBL-001..009}).
 */
public interface ObligationHandler {

    /** Returns the unique obligation type identifier (e.g. {@code REQUIRE_JUSTIFICATION}). */
    String obligationType();

    /** Returns the supported activation triggers. */
    Set<ObligationTrigger> supportedTriggers();

    /** Returns the canonical fulfillment barrier required for this obligation type. */
    ObligationFulfillmentBarrier requiredBarrier();

    /**
     * Merges two directives of this obligation type commutatively, associatively, and idempotently
     * ({@code PCB-OBL-001}).
     */
    ObligationMergeOutcome merge(ObligationDirective left, ObligationDirective right);

    /**
     * Executes fulfillment at the required barrier against the supplied execution context.
     */
    ObligationFulfillmentResult fulfill(ObligationDirective directive, Map<String, Object> executionContext);
}
