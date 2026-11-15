package org.praxisplatform.authz.contracts.context;

/**
 * Explicit cause accompanying {@link FactResolutionStatus#UNAVAILABLE} ({@code CTX-RES-003}).
 */
public enum FactUnavailableCause {
    NONE,
    ACCESS_DENIED,
    SOURCE_TIMEOUT,
    NOT_LOADED_IN_PHASE,
    UNSUPPORTED_SOURCE
}
