package org.praxisplatform.authz.contracts.obligation;

/**
 * Activation trigger of an {@link org.praxisplatform.authz.contracts.envelope.ObligationDirective} ({@code CC10}).
 */
public enum ObligationTrigger {
    ON_PERMIT,
    ON_DENY,
    ALWAYS
}
