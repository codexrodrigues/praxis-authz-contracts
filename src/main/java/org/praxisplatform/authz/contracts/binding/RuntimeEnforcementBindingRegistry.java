package org.praxisplatform.authz.contracts.binding;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.praxisplatform.authz.contracts.decisionpoint.EnforcementCapability;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;

/**
 * Registry of {@link RuntimeEnforcementBinding}s installed in a host application ({@code CC06}).
 */
public interface RuntimeEnforcementBindingRegistry {

    /** Returns all registered runtime enforcement bindings. */
    Set<RuntimeEnforcementBinding> listBindings();

    /** Finds all bindings for a decision point key and evaluation mode. */
    List<RuntimeEnforcementBinding> findBindings(String pointKey, EvaluationMode mode);

    /** Finds the unique binding for a decision point key, evaluation mode, and capability. */
    Optional<RuntimeEnforcementBinding> findBinding(
            String pointKey,
            EvaluationMode mode,
            EnforcementCapability capability
    );
}
