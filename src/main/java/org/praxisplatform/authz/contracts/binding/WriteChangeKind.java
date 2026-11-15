package org.praxisplatform.authz.contracts.binding;

/**
 * Semantic change kind of a field inside a caller's {@link WriteIntent} ({@code ENF-FW-001..004B}).
 */
public enum WriteChangeKind {
    SET,
    CLEAR_EXPLICIT_NULL,
    REMOVE
}
