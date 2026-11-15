package org.praxisplatform.authz.contracts.context;

/**
 * Deterministic stage at which a fact is resolved during context composition ({@code CTX-CONTRACT-002}).
 */
public enum FactResolutionStage {
    EXTRACT,
    ENRICH,
    DERIVE
}
