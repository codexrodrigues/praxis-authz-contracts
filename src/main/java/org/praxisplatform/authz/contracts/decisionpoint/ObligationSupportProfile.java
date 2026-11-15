package org.praxisplatform.authz.contracts.decisionpoint;

import java.util.Set;

/**
 * Declares which obligation types and fulfillment barrier profiles a decision point supports ({@code DPC-CAP-004}).
 *
 * @param supportedTypes supported obligation type identifiers
 * @param supportedFulfillmentProfiles supported fulfillment barrier names
 */
public record ObligationSupportProfile(
        Set<String> supportedTypes,
        Set<String> supportedFulfillmentProfiles
) {

    /** Normalizes sets to immutable copies. */
    public ObligationSupportProfile {
        supportedTypes = supportedTypes == null ? Set.of() : Set.copyOf(supportedTypes);
        supportedFulfillmentProfiles = supportedFulfillmentProfiles == null
                ? Set.of()
                : Set.copyOf(supportedFulfillmentProfiles);
    }
}
