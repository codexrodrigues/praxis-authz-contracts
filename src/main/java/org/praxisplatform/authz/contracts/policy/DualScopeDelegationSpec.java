package org.praxisplatform.authz.contracts.policy;

import java.util.Collections;
import java.util.Objects;
import java.util.Set;

/**
 * Native dual-scope functional delegation specification ({@code cedente} vs {@code cessionario},
 * {@code CC01}, {@code PDP-SEM-004}).
 *
 * @param mode delegation mode (e.g. {@code CEDENTE_CESSIONARIO_SPLIT})
 * @param cedenteFactPath canonical resource fact path for the origin organization unit
 * @param cessionarioFactPath canonical resource fact path for the host/receiving organization unit
 * @param cedenteExclusiveWriteAttributes attributes writable exclusively by the origin authority
 * @param cessionarioAllowedWriteAttributes attributes writable by the receiving authority
 */
public record DualScopeDelegationSpec(
        String mode,
        String cedenteFactPath,
        String cessionarioFactPath,
        Set<String> cedenteExclusiveWriteAttributes,
        Set<String> cessionarioAllowedWriteAttributes
) {

    /** Validates non-overlapping exclusive write attribute sets between {@code cedente} and {@code cessionario}. */
    public DualScopeDelegationSpec {
        mode = requireNonBlank(mode, "mode");
        cedenteFactPath = requireNonBlank(cedenteFactPath, "cedenteFactPath");
        cessionarioFactPath = requireNonBlank(cessionarioFactPath, "cessionarioFactPath");
        cedenteExclusiveWriteAttributes = cedenteExclusiveWriteAttributes == null
                ? Set.of()
                : Set.copyOf(cedenteExclusiveWriteAttributes);
        cessionarioAllowedWriteAttributes = cessionarioAllowedWriteAttributes == null
                ? Set.of()
                : Set.copyOf(cessionarioAllowedWriteAttributes);
        if (!Collections.disjoint(cedenteExclusiveWriteAttributes, cessionarioAllowedWriteAttributes)) {
            throw new IllegalArgumentException(
                    "cedenteExclusiveWriteAttributes and cessionarioAllowedWriteAttributes must be disjoint (PDP-SEM-004)");
        }
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
