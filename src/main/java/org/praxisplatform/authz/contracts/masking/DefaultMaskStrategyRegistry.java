package org.praxisplatform.authz.contracts.masking;

import java.util.Collection;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.praxisplatform.authz.contracts.context.FactValueType;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;

/**
 * Canonical implementation of {@link MaskStrategyRegistry} pre-configured with the 7 standard
 * platform strategies ({@code OMIT}, {@code NULLIFY}, {@code REDACT_CONSTANT}, {@code HASH_TOKEN_KEYED},
 * {@code SUMMARY_ONLY}, {@code CPF_CNPJ_PARTIAL}, {@code PARTIAL_MASK}) and the algebraic merge lattice
 * ({@code CC09}, {@code PCB-MASK-001..005}).
 */
public final class DefaultMaskStrategyRegistry implements MaskStrategyRegistry {

    private static final Set<FactValueType> ALL_TYPES = EnumSet.allOf(FactValueType.class);

    private final Map<String, MaskStrategyDescriptor> byId;

    /** Constructs the default registry with the 7 canonical masking strategies. */
    public DefaultMaskStrategyRegistry() {
        this(defaultDescriptors());
    }

    /** Constructs a registry from custom descriptors. */
    public DefaultMaskStrategyRegistry(Collection<MaskStrategyDescriptor> descriptors) {
        Objects.requireNonNull(descriptors, "descriptors is required");
        Map<String, MaskStrategyDescriptor> map = new LinkedHashMap<>();
        for (MaskStrategyDescriptor descriptor : descriptors) {
            Objects.requireNonNull(descriptor, "descriptor must not be null");
            map.put(descriptor.strategyId(), descriptor);
        }
        this.byId = Map.copyOf(map);
    }

    /** Returns the 7 canonical masking strategy descriptors from {@code CC09} §5.2.2. */
    public static List<MaskStrategyDescriptor> defaultDescriptors() {
        return List.of(
                new MaskStrategyDescriptor("OMIT", 100, ALL_TYPES, null, true, Set.of()),
                new MaskStrategyDescriptor("NULLIFY", 90, ALL_TYPES, null, true, Set.of()),
                new MaskStrategyDescriptor(
                        "REDACT_CONSTANT",
                        80,
                        Set.of(FactValueType.STRING),
                        FactValueType.STRING,
                        false,
                        Set.of("replacement")),
                new MaskStrategyDescriptor(
                        "HASH_TOKEN_KEYED",
                        70,
                        Set.of(FactValueType.STRING, FactValueType.INT64),
                        FactValueType.STRING,
                        false,
                        Set.of("keyAlias", "truncateChars")),
                new MaskStrategyDescriptor(
                        "SUMMARY_ONLY",
                        60,
                        ALL_TYPES,
                        FactValueType.STRING,
                        false,
                        Set.of("summaryFormat")),
                new MaskStrategyDescriptor(
                        "CPF_CNPJ_PARTIAL",
                        50,
                        Set.of(FactValueType.STRING),
                        FactValueType.STRING,
                        false,
                        Set.of()),
                new MaskStrategyDescriptor(
                        "PARTIAL_MASK",
                        50,
                        Set.of(FactValueType.STRING),
                        FactValueType.STRING,
                        false,
                        Set.of("visiblePrefix", "visibleSuffix", "maskChar"))
        );
    }

    @Override
    public Optional<MaskStrategyDescriptor> findById(String strategyId) {
        return Optional.ofNullable(byId.get(strategyId));
    }

    @Override
    public Set<MaskStrategyDescriptor> listAll() {
        return Set.copyOf(byId.values());
    }

    @Override
    public MaskMergeOutcome merge(MaskDirective left, MaskDirective right) {
        Objects.requireNonNull(left, "left is required");
        Objects.requireNonNull(right, "right is required");
        if (!left.attributeId().equals(right.attributeId())) {
            throw new IllegalArgumentException(
                    "Cannot merge MaskDirectives for different attributeIds: '"
                            + left.attributeId() + "' vs '" + right.attributeId() + "'");
        }

        MaskStrategyDescriptor leftDesc = byId.get(left.strategyId());
        MaskStrategyDescriptor rightDesc = byId.get(right.strategyId());
        if (leftDesc == null || rightDesc == null) {
            return new MaskMergeOutcome(
                    MaskMergeStatus.MASK_CONFLICT,
                    null,
                    "AUTHZ_UNKNOWN_MASK_STRATEGY");
        }

        // Same strategy: idempotent if parameters match; conflict if parameters diverge
        if (left.strategyId().equals(right.strategyId())) {
            if (left.parameters().equals(right.parameters())) {
                return new MaskMergeOutcome(MaskMergeStatus.MERGED, left, null);
            }
            return new MaskMergeOutcome(
                    MaskMergeStatus.MASK_CONFLICT,
                    null,
                    "AUTHZ_MASK_PARAMETER_CONFLICT:" + left.strategyId());
        }

        // Different strategies with equal severity rank (e.g. CPF_CNPJ_PARTIAL vs PARTIAL_MASK at rank 50)
        // are incomparable in the partial order -> MASK_CONFLICT
        if (leftDesc.severityRank() == rightDesc.severityRank()) {
            return new MaskMergeOutcome(
                    MaskMergeStatus.MASK_CONFLICT,
                    null,
                    "AUTHZ_INCOMPARABLE_MASK_STRATEGIES:" + left.strategyId() + "_VS_" + right.strategyId());
        }

        // Strictly comparable in the lattice: higher severityRank dominates
        MaskDirective dominant = leftDesc.severityRank() > rightDesc.severityRank() ? left : right;
        return new MaskMergeOutcome(MaskMergeStatus.MERGED, dominant, null);
    }

    @Override
    public MaskMergeOutcome resolveForField(List<MaskDirective> directives, boolean fieldUseValueDenied) {
        Objects.requireNonNull(directives, "directives is required");
        if (fieldUseValueDenied) {
            return new MaskMergeOutcome(MaskMergeStatus.DOMINATED_BY_FIELD_USE_DENY, null, null);
        }
        if (directives.isEmpty()) {
            throw new IllegalArgumentException("directives must not be empty when fieldUseValueDenied is false");
        }
        MaskDirective current = directives.get(0);
        if (findById(current.strategyId()).isEmpty()) {
            return new MaskMergeOutcome(MaskMergeStatus.MASK_CONFLICT, null, "AUTHZ_UNKNOWN_MASK_STRATEGY");
        }
        for (int i = 1; i < directives.size(); i++) {
            MaskMergeOutcome step = merge(current, directives.get(i));
            if (step.status() != MaskMergeStatus.MERGED) {
                return step;
            }
            current = step.effectiveDirective();
        }
        return new MaskMergeOutcome(MaskMergeStatus.MERGED, current, null);
    }

    @Override
    public boolean isCompatibleWithTargetField(
            MaskDirective directive,
            FactValueType targetFieldType,
            boolean targetFieldNullable
    ) {
        Objects.requireNonNull(directive, "directive is required");
        Objects.requireNonNull(targetFieldType, "targetFieldType is required");
        MaskStrategyDescriptor desc = byId.get(directive.strategyId());
        if (desc == null) {
            return false;
        }
        if (desc.requiresNullableTargetField() && !targetFieldNullable) {
            return false;
        }
        if (!desc.supportedInputTypes().contains(targetFieldType)) {
            return false;
        }
        return desc.allowedParameterNames().containsAll(directive.parameters().keySet());
    }
}
