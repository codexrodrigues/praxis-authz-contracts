package org.praxisplatform.authz.contracts.obligation;

import java.util.Optional;
import java.util.Set;
import org.praxisplatform.authz.contracts.envelope.ObligationDirective;

/**
 * Host registry of {@link ObligationHandler}s ({@code CC10}).
 */
public interface ObligationHandlerRegistry {

    /** Finds the handler registered for the given obligation type. */
    Optional<ObligationHandler> findHandler(String obligationType);

    /** Returns all registered obligation type identifiers. */
    Set<String> listRegisteredTypes();

    /**
     * Merges two {@link ObligationDirective}s via the registered handler, or returns
     * {@link ObligationMergeStatus#UNKNOWN_OBLIGATION_TYPE} when unregistered.
     */
    ObligationMergeOutcome merge(ObligationDirective left, ObligationDirective right);
}
