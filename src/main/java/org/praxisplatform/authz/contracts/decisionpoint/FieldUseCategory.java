package org.praxisplatform.authz.contracts.decisionpoint;

import java.util.Objects;

/**
 * Frozen 6-category vocabulary for {@link EnforcementCapability#FIELD_USE}
 * ({@code decision-platform-architecture-baseline-v1.md} §16, {@code ENF-FU-012}).
 *
 * <p>{@code EXPORT} and {@code LOOKUP} are strictly forbidden as {@code FIELD_USE} categories:
 * they are decision-point operation contexts where disclosing a field uses {@link #VALUE}.</p>
 */
public enum FieldUseCategory {
    VALUE,
    FILTER,
    SORT,
    GROUP,
    AGGREGATE,
    JOIN;

    /**
     * Parses a wire category name, explicitly rejecting forbidden operation-context aliases
     * ({@code EXPORT}, {@code LOOKUP}, {@code GROUP_BY}).
     *
     * @param wireName wire category token
     * @return canonical {@link FieldUseCategory}
     */
    public static FieldUseCategory fromWireName(String wireName) {
        Objects.requireNonNull(wireName, "wireName is required");
        String normalized = wireName.trim().toUpperCase();
        if ("EXPORT".equals(normalized) || "LOOKUP".equals(normalized)) {
            throw new IllegalArgumentException(
                    "'" + normalized + "' is a decision-point operation context, not a valid FieldUseCategory (ENF-FU-012); use VALUE at that decision point");
        }
        if ("GROUP_BY".equals(normalized)) {
            throw new IllegalArgumentException(
                    "'GROUP_BY' is not a canonical FieldUseCategory (ENF-FU-012); use GROUP");
        }
        return FieldUseCategory.valueOf(normalized);
    }
}
