package org.praxisplatform.authz.contracts.binding;

/**
 * Canonical host enforcement phase in which a {@link RuntimeEnforcementBinding} executes ({@code CC06}).
 */
public enum HostEnforcementPhase {
    ADMISSION,
    REQUEST_QUERY,
    TARGET_RESOLUTION,
    PRE_MUTATION,
    PRE_COMMIT_OUTBOX,
    PRE_DISCLOSURE
}
