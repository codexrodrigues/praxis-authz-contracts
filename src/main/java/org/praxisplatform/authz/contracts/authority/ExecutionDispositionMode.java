package org.praxisplatform.authz.contracts.authority;

/**
 * Operational rollout disposition mode orthogonal to {@code PointAuthorityMode} ({@code CC12}, {@code BND-SEM-001}).
 */
public enum ExecutionDispositionMode {
    TEST,
    SHADOW,
    PREFLIGHT,
    AUTHORITATIVE_EXECUTION
}
