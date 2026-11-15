package org.praxisplatform.authz.contracts.masking;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.praxisplatform.authz.contracts.context.FactValueType;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;

/**
 * Host registry of server-side security masking strategies and algebraic merge lattice ({@code CC09}).
 */
public interface MaskStrategyRegistry {

    /** Looks up a strategy descriptor by its identifier. */
    Optional<MaskStrategyDescriptor> findById(String strategyId);

    /** Returns all registered masking strategy descriptors. */
    Set<MaskStrategyDescriptor> listAll();

    /**
     * Merges two {@link MaskDirective}s targeting the same {@code attributeId} according to the
     * commutative, associative, and idempotent masking lattice ({@code PCB-MASK-001..005}).
     */
    MaskMergeOutcome merge(MaskDirective left, MaskDirective right);

    /**
     * Resolves the effective masking outcome for a single field across one or more {@link MaskDirective}s,
     * giving absolute precedence to {@code FIELD_USE(VALUE) == DENY} ({@link MaskMergeStatus#DOMINATED_BY_FIELD_USE_DENY},
     * {@code PCB-MASK-001}).
     */
    MaskMergeOutcome resolveForField(List<MaskDirective> directives, boolean fieldUseValueDenied);

    /**
     * Validates whether a {@link MaskDirective} is compatible with the target DTO field's type and
     * nullability ({@code ENF-MSK-004..008}).
     */
    boolean isCompatibleWithTargetField(
            MaskDirective directive,
            FactValueType targetFieldType,
            boolean targetFieldNullable
    );
}
