package org.praxisplatform.authz.contracts.binding;

import java.util.Objects;

/**
 * Single field mutation captured in a {@link WriteIntent} prior to server-side {@code hydrate*}
 * ({@code ENF-FW-001..004B}).
 *
 * @param canonicalWirePath JSON Pointer / wire path in the request DTO (e.g. {@code /substitutoMatricula})
 * @param attributeId canonical {@code @DomainLineage.attributeId}
 * @param changeKind whether the field is being {@code SET}, {@code CLEAR_EXPLICIT_NULL}, or {@code REMOVE}d
 * @param declaredValueProjection projected value when {@code changeKind == SET}, otherwise {@code null}
 */
public record WriteFieldChange(
        String canonicalWirePath,
        String attributeId,
        WriteChangeKind changeKind,
        Object declaredValueProjection
) {

    /** Validates wire path, attributeId, and value presence vs {@link WriteChangeKind}. */
    public WriteFieldChange {
        canonicalWirePath = requireNonBlank(canonicalWirePath, "canonicalWirePath");
        if (!canonicalWirePath.startsWith("/")) {
            throw new IllegalArgumentException("canonicalWirePath must be a JSON Pointer starting with '/': " + canonicalWirePath);
        }
        attributeId = requireNonBlank(attributeId, "attributeId");
        changeKind = Objects.requireNonNull(changeKind, "changeKind is required");
        if (changeKind == WriteChangeKind.SET && declaredValueProjection == null) {
            throw new IllegalArgumentException(
                    "WriteFieldChange with changeKind=SET must provide non-null declaredValueProjection; use CLEAR_EXPLICIT_NULL for explicit nulls");
        }
        if (changeKind != WriteChangeKind.SET && declaredValueProjection != null) {
            throw new IllegalArgumentException(
                    "WriteFieldChange with changeKind=" + changeKind + " must have null declaredValueProjection");
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
