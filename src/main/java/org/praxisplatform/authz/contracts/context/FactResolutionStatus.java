package org.praxisplatform.authz.contracts.context;

/**
 * Frozen 6-state fact resolution status defined by {@code decision-platform-architecture-baseline-v1.md} §13.
 */
public enum FactResolutionStatus {
    PRESENT,
    NULL,
    ABSENT,
    STALE,
    UNAVAILABLE,
    ERROR
}
