package org.praxisplatform.authz.contracts.annotation;

/**
 * Standard masking strategies supported by {@link AuthzMask}, aligned 1:1 with
 * {@link org.praxisplatform.authz.contracts.masking.DefaultMaskStrategyRegistry}.
 */
public enum AuthzMaskStrategy {

    /** Completely omits the property from detached DTO projections (rank 100; requires nullable or optional field). */
    OMIT("OMIT", 100),

    /** Replaces the property value with {@code null} (rank 90; requires nullable target field). */
    NULLIFY("NULLIFY", 90),

    /** Replaces a string value with a fixed constant placeholder such as {@code "***"} (rank 80). */
    REDACT_CONSTANT("REDACT_CONSTANT", 80),

    /** Replaces a string or integer value with a keyed deterministic hash token (rank 70). */
    HASH_TOKEN_KEYED("HASH_TOKEN_KEYED", 70),

    /** Replaces the value with a formatted non-sensitive summary string (rank 60). */
    SUMMARY_ONLY("SUMMARY_ONLY", 60),

    /** Applies standard national tax/registry document partial masking (rank 50). */
    CPF_CNPJ_PARTIAL("CPF_CNPJ_PARTIAL", 50),

    /** Preserves configurable prefix/suffix characters and masks the remainder (rank 50). */
    PARTIAL_MASK("PARTIAL_MASK", 50),

    /** Host-registered custom strategy identified by {@link AuthzMask#customStrategyId()}. */
    CUSTOM("", 0);

    private final String strategyId;
    private final int severityRank;

    AuthzMaskStrategy(String strategyId, int severityRank) {
        this.strategyId = strategyId;
        this.severityRank = severityRank;
    }

    /**
     * Canonical strategy identifier matching
     * {@link org.praxisplatform.authz.contracts.masking.MaskStrategyDescriptor#strategyId()}.
     *
     * @return strategy identifier, or empty string for {@link #CUSTOM}
     */
    public String strategyId() {
        return strategyId;
    }

    /**
     * Severity rank in the standard commutative masking lattice ({@code 50..100}), or {@code 0}
     * for {@link #CUSTOM}.
     *
     * @return lattice severity rank
     */
    public int severityRank() {
        return severityRank;
    }
}
