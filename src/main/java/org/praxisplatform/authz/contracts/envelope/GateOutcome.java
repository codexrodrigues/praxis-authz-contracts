package org.praxisplatform.authz.contracts.envelope;

/**
 * Five-state gate outcome returned by an authorization provider ({@code CC07}, {@code ENF-ENV-001}).
 */
public enum GateOutcome {
    ALLOW,
    DENY,
    NOT_APPLICABLE,
    INCONCLUSIVE,
    TECHNICAL_ERROR
}
