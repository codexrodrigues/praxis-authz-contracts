package org.praxisplatform.authz.contracts.policy;

import java.util.Collections;
import java.util.Objects;
import java.util.Set;

/**
 * Native dual-scope functional delegation specification ({@code origin} vs {@code destination},
 * {@code CC01}, {@code PDP-SEM-004}).
 *
 * <p>Defines disjoint attribute write partitions between an authoritative origin scope (the owning
 * entity/unit that originates a record or assignment) and a delegated destination scope (the
 * receiving unit authorized to inspect or update designated attributes).</p>
 *
 * @param mode delegation split mode (e.g. {@link #ORIGIN_DESTINATION_SPLIT},
 *     {@link #ORIGIN_ONLY_WRITE}, {@link #READ_ONLY_DESTINATION})
 * @param originFactPath canonical resource fact path for the origin organization unit
 * @param destinationFactPath canonical resource fact path for the delegated/receiving organization unit
 * @param originExclusiveWriteAttributes attributes writable exclusively by the origin authority
 * @param destinationAllowedWriteAttributes attributes writable by the delegated/receiving authority
 */
public record DualScopeDelegationSpec(
        String mode,
        String originFactPath,
        String destinationFactPath,
        Set<String> originExclusiveWriteAttributes,
        Set<String> destinationAllowedWriteAttributes
) {

    /** Both origin and destination scopes may mutate their respective disjoint field partitions. */
    public static final String ORIGIN_DESTINATION_SPLIT = "ORIGIN_DESTINATION_SPLIT";

    /** Only callers holding origin custody may mutate attributes; destination-only callers are denied. */
    public static final String ORIGIN_ONLY_WRITE = "ORIGIN_ONLY_WRITE";

    /** Destination callers have read-only visibility; mutations require origin custody. */
    public static final String READ_ONLY_DESTINATION = "READ_ONLY_DESTINATION";

    /**
     * Legacy domain alias for {@link #ORIGIN_DESTINATION_SPLIT}.
     *
     * @deprecated Use {@link #ORIGIN_DESTINATION_SPLIT}.
     */
    @Deprecated(since = "0.1.0-beta.2")
    public static final String CEDENTE_CESSIONARIO_SPLIT = "CEDENTE_CESSIONARIO_SPLIT";

    /**
     * Legacy domain alias for {@link #ORIGIN_ONLY_WRITE}.
     *
     * @deprecated Use {@link #ORIGIN_ONLY_WRITE}.
     */
    @Deprecated(since = "0.1.0-beta.2")
    public static final String CEDENTE_ONLY_WRITE = "CEDENTE_ONLY_WRITE";

    /**
     * Legacy domain alias for {@link #READ_ONLY_DESTINATION}.
     *
     * @deprecated Use {@link #READ_ONLY_DESTINATION}.
     */
    @Deprecated(since = "0.1.0-beta.2")
    public static final String READ_ONLY_CESSIONARIO = "READ_ONLY_CESSIONARIO";

    /** Validates non-overlapping write attribute sets between {@code origin} and {@code destination}. */
    public DualScopeDelegationSpec {
        mode = requireNonBlank(mode, "mode");
        originFactPath = requireNonBlank(originFactPath, "originFactPath");
        destinationFactPath = requireNonBlank(destinationFactPath, "destinationFactPath");
        originExclusiveWriteAttributes = originExclusiveWriteAttributes == null
                ? Set.of()
                : Set.copyOf(originExclusiveWriteAttributes);
        destinationAllowedWriteAttributes = destinationAllowedWriteAttributes == null
                ? Set.of()
                : Set.copyOf(destinationAllowedWriteAttributes);
        if (!Collections.disjoint(originExclusiveWriteAttributes, destinationAllowedWriteAttributes)) {
            throw new IllegalArgumentException(
                    "originExclusiveWriteAttributes and destinationAllowedWriteAttributes must be disjoint (PDP-SEM-004)");
        }
    }

    /**
     * Creates a neutral dual-scope delegation specification with explicit origin and destination scopes.
     *
     * @param mode delegation split mode (e.g. {@link #ORIGIN_DESTINATION_SPLIT})
     * @param originFactPath canonical resource fact path for the origin unit
     * @param destinationFactPath canonical resource fact path for the destination unit
     * @param originExclusiveWriteAttributes attributes writable exclusively by the origin authority
     * @param destinationAllowedWriteAttributes attributes writable by the destination authority
     * @return immutable {@link DualScopeDelegationSpec}
     */
    public static DualScopeDelegationSpec ofOriginAndDestination(
            String mode,
            String originFactPath,
            String destinationFactPath,
            Set<String> originExclusiveWriteAttributes,
            Set<String> destinationAllowedWriteAttributes
    ) {
        return new DualScopeDelegationSpec(
                mode,
                originFactPath,
                destinationFactPath,
                originExclusiveWriteAttributes,
                destinationAllowedWriteAttributes
        );
    }

    /**
     * Creates a split-write delegation specification ({@link #ORIGIN_DESTINATION_SPLIT}) with explicit
     * origin and destination scopes.
     *
     * @param originFactPath canonical resource fact path for the origin unit
     * @param destinationFactPath canonical resource fact path for the destination unit
     * @param originExclusiveWriteAttributes attributes writable exclusively by the origin authority
     * @param destinationAllowedWriteAttributes attributes writable by the destination authority
     * @return immutable {@link DualScopeDelegationSpec} in {@link #ORIGIN_DESTINATION_SPLIT} mode
     */
    public static DualScopeDelegationSpec ofOriginAndDestination(
            String originFactPath,
            String destinationFactPath,
            Set<String> originExclusiveWriteAttributes,
            Set<String> destinationAllowedWriteAttributes
    ) {
        return new DualScopeDelegationSpec(
                ORIGIN_DESTINATION_SPLIT,
                originFactPath,
                destinationFactPath,
                originExclusiveWriteAttributes,
                destinationAllowedWriteAttributes
        );
    }

    /**
     * Returns {@code true} when this delegation mode permits destination custody callers to mutate
     * attributes in {@link #destinationAllowedWriteAttributes()}.
     *
     * @return {@code true} for {@link #ORIGIN_DESTINATION_SPLIT} or legacy {@code CEDENTE_CESSIONARIO_SPLIT}
     */
    public boolean allowsDestinationWrites() {
        return ORIGIN_DESTINATION_SPLIT.equals(mode) || CEDENTE_CESSIONARIO_SPLIT.equals(mode);
    }

    /**
     * Returns {@code true} when this delegation mode forbids mutations by callers holding only
     * destination custody.
     *
     * @return {@code true} for {@link #ORIGIN_ONLY_WRITE}, {@link #READ_ONLY_DESTINATION}, and legacy aliases
     */
    public boolean forbidsDestinationOnlyWrites() {
        return ORIGIN_ONLY_WRITE.equals(mode)
                || READ_ONLY_DESTINATION.equals(mode)
                || CEDENTE_ONLY_WRITE.equals(mode)
                || READ_ONLY_CESSIONARIO.equals(mode);
    }

    /**
     * Backward-compatible delegate for {@link #originFactPath()}.
     *
     * @return canonical resource fact path for the origin organization unit
     * @deprecated Use {@link #originFactPath()}.
     */
    @Deprecated(since = "0.1.0-beta.2")
    public String cedenteFactPath() {
        return originFactPath;
    }

    /**
     * Backward-compatible delegate for {@link #destinationFactPath()}.
     *
     * @return canonical resource fact path for the delegated/receiving organization unit
     * @deprecated Use {@link #destinationFactPath()}.
     */
    @Deprecated(since = "0.1.0-beta.2")
    public String cessionarioFactPath() {
        return destinationFactPath;
    }

    /**
     * Backward-compatible delegate for {@link #originExclusiveWriteAttributes()}.
     *
     * @return attributes writable exclusively by the origin authority
     * @deprecated Use {@link #originExclusiveWriteAttributes()}.
     */
    @Deprecated(since = "0.1.0-beta.2")
    public Set<String> cedenteExclusiveWriteAttributes() {
        return originExclusiveWriteAttributes;
    }

    /**
     * Backward-compatible delegate for {@link #destinationAllowedWriteAttributes()}.
     *
     * @return attributes writable by the delegated/receiving authority
     * @deprecated Use {@link #destinationAllowedWriteAttributes()}.
     */
    @Deprecated(since = "0.1.0-beta.2")
    public Set<String> cessionarioAllowedWriteAttributes() {
        return destinationAllowedWriteAttributes;
    }

    private static String requireNonBlank(String value, String field) {
        Objects.requireNonNull(value, field + " is required");
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return trimmed;
    }
}
