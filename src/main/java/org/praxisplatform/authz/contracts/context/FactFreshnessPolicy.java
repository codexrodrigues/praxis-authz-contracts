package org.praxisplatform.authz.contracts.context;

/**
 * Freshness policy for enriched or cached facts ({@code CTX-RES-004}).
 *
 * @param maxAgeSeconds maximum acceptable age in seconds before the fact becomes {@link FactResolutionStatus#STALE}
 */
public record FactFreshnessPolicy(long maxAgeSeconds) {

    /** Validates positive maximum age. */
    public FactFreshnessPolicy {
        if (maxAgeSeconds <= 0) {
            throw new IllegalArgumentException("maxAgeSeconds must be positive");
        }
    }
}
