package org.praxisplatform.authz.contracts.datascope;

/**
 * Three-valued outcome of a {@link DataScopePlan} ({@code CC03}, {@code DSP-PLAN-001..004}).
 *
 * <p>Per {@code DSP-PLAN-002}, {@link #ALL} means "no additional dynamic policy filter" and never
 * bypasses mandatory host {@code hardScope} / tenant isolation.</p>
 */
public enum DataScopeOutcome {
    ALL,
    NONE,
    FILTER
}
