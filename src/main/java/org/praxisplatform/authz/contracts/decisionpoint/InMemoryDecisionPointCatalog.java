package org.praxisplatform.authz.contracts.decisionpoint;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Immutable in-memory implementation of {@link DecisionPointCatalog} rejecting duplicate {@code pointKey}s.
 */
public final class InMemoryDecisionPointCatalog implements DecisionPointCatalog {

    private final Map<String, DecisionPointDescriptor> byPointKey;

    /**
     * Constructs an immutable catalog from the provided descriptors.
     *
     * @param descriptors collection of decision point descriptors
     */
    public InMemoryDecisionPointCatalog(Collection<DecisionPointDescriptor> descriptors) {
        Objects.requireNonNull(descriptors, "descriptors is required");
        Map<String, DecisionPointDescriptor> map = new LinkedHashMap<>();
        for (DecisionPointDescriptor descriptor : descriptors) {
            Objects.requireNonNull(descriptor, "descriptor element must not be null");
            String key = descriptor.identity().pointKey();
            if (map.putIfAbsent(key, descriptor) != null) {
                throw new IllegalArgumentException("Duplicate DecisionPointDescriptor pointKey: " + key);
            }
        }
        this.byPointKey = Map.copyOf(map);
    }

    @Override
    public Set<DecisionPointDescriptor> listAll() {
        return Set.copyOf(byPointKey.values());
    }

    @Override
    public Optional<DecisionPointDescriptor> findByPointKey(String pointKey) {
        return Optional.ofNullable(byPointKey.get(pointKey));
    }

    @Override
    public Optional<DecisionPointDescriptor> findByResourceOperation(String resourceKey, String operationId) {
        String key = DecisionPointIdentity.formatPointKey(
                DecisionPointKind.RESOURCE_OPERATION, resourceKey, operationId);
        return findByPointKey(key);
    }

    @Override
    public Optional<DecisionPointDescriptor> findByWorkflowAction(String resourceKey, String actionId) {
        String key = DecisionPointIdentity.formatPointKey(
                DecisionPointKind.WORKFLOW_ACTION, resourceKey, actionId);
        return findByPointKey(key);
    }
}
