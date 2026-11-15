package org.praxisplatform.authz.contracts.binding;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.praxisplatform.authz.contracts.decisionpoint.EnforcementCapability;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;

/**
 * Immutable in-memory implementation of {@link RuntimeEnforcementBindingRegistry} that enforces
 * {@code BND-SEM-005}: at most one dynamic authoritative provider binding may be registered for each
 * {@code (pointKey, evaluationMode, enforcementCapability)} tuple.
 */
public final class InMemoryRuntimeEnforcementBindingRegistry implements RuntimeEnforcementBindingRegistry {

    private final Set<RuntimeEnforcementBinding> allBindings;
    private final Map<String, RuntimeEnforcementBinding> byTupleKey;

    /**
     * Constructs an immutable registry and validates {@code BND-SEM-005} uniqueness.
     *
     * @param bindings collection of runtime enforcement bindings
     */
    public InMemoryRuntimeEnforcementBindingRegistry(Collection<RuntimeEnforcementBinding> bindings) {
        Objects.requireNonNull(bindings, "bindings is required");
        Set<RuntimeEnforcementBinding> set = new LinkedHashSet<>();
        Map<String, RuntimeEnforcementBinding> tupleMap = new LinkedHashMap<>();
        for (RuntimeEnforcementBinding binding : bindings) {
            Objects.requireNonNull(binding, "binding element must not be null");
            String tupleKey = tupleKey(
                    binding.decisionPointRef().pointKey(),
                    binding.evaluationMode(),
                    binding.enforcementCapability()
            );
            RuntimeEnforcementBinding existing = tupleMap.putIfAbsent(tupleKey, binding);
            if (existing != null) {
                throw new IllegalArgumentException(
                        "Multiple dynamic authoritative provider bindings registered for tuple ("
                                + tupleKey + "): '" + existing.dynamicAuthoritativeProviderBinding()
                                + "' and '" + binding.dynamicAuthoritativeProviderBinding() + "' (BND-SEM-005)");
            }
            set.add(binding);
        }
        this.allBindings = Set.copyOf(set);
        this.byTupleKey = Map.copyOf(tupleMap);
    }

    @Override
    public Set<RuntimeEnforcementBinding> listBindings() {
        return allBindings;
    }

    @Override
    public List<RuntimeEnforcementBinding> findBindings(String pointKey, EvaluationMode mode) {
        List<RuntimeEnforcementBinding> matches = new ArrayList<>();
        for (RuntimeEnforcementBinding binding : allBindings) {
            if (binding.decisionPointRef().pointKey().equals(pointKey) && binding.evaluationMode() == mode) {
                matches.add(binding);
            }
        }
        return List.copyOf(matches);
    }

    @Override
    public Optional<RuntimeEnforcementBinding> findBinding(
            String pointKey,
            EvaluationMode mode,
            EnforcementCapability capability
    ) {
        return Optional.ofNullable(byTupleKey.get(tupleKey(pointKey, mode, capability)));
    }

    private static String tupleKey(String pointKey, EvaluationMode mode, EnforcementCapability capability) {
        return pointKey + "|" + mode.name() + "|" + capability.name();
    }
}
