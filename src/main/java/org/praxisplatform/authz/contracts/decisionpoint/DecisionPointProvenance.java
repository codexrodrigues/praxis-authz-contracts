package org.praxisplatform.authz.contracts.decisionpoint;

import java.util.Set;

/**
 * Provenance metadata describing how a {@link DecisionPointDescriptor} was derived ({@code DPC-PROV-001}).
 *
 * @param sources metadata sources contributing to this descriptor
 * @param declaredExtensions OpenAPI/metadata extensions published for this point
 */
public record DecisionPointProvenance(
        Set<String> sources,
        Set<String> declaredExtensions
) {

    /** Normalizes sets to immutable copies. */
    public DecisionPointProvenance {
        sources = sources == null ? Set.of() : Set.copyOf(sources);
        declaredExtensions = declaredExtensions == null ? Set.of() : Set.copyOf(declaredExtensions);
    }
}
