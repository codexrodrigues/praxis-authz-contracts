package org.praxisplatform.authz.contracts.compatibility;

/**
 * Completeness status of an {@link ImpactGraphBaseline} ({@code CC08}, {@code BND-IMP-001..004}).
 *
 * <p>Only {@link #COMPLETE} allows publication of an authorization policy for authoritative execution.</p>
 */
public enum ImpactCompletenessStatus {
    COMPLETE,
    PARTIAL,
    STALE,
    UNKNOWN
}
