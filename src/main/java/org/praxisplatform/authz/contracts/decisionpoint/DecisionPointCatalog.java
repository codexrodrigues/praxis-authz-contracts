package org.praxisplatform.authz.contracts.decisionpoint;

import java.util.Optional;
import java.util.Set;

/**
 * Read-only catalog of registered {@link DecisionPointDescriptor}s ({@code CC05}).
 */
public interface DecisionPointCatalog {

    /** Returns all registered decision point descriptors. */
    Set<DecisionPointDescriptor> listAll();

    /** Finds a descriptor by its canonical {@code pointKey}. */
    Optional<DecisionPointDescriptor> findByPointKey(String pointKey);

    /** Finds a {@link DecisionPointKind#RESOURCE_OPERATION} descriptor by resourceKey and operationId. */
    Optional<DecisionPointDescriptor> findByResourceOperation(String resourceKey, String operationId);

    /** Finds a {@link DecisionPointKind#WORKFLOW_ACTION} descriptor by resourceKey and actionId. */
    Optional<DecisionPointDescriptor> findByWorkflowAction(String resourceKey, String actionId);
}
