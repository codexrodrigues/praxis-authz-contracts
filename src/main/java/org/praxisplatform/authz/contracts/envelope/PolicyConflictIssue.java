package org.praxisplatform.authz.contracts.envelope;

import java.util.Objects;
import java.util.Set;

/**
 * Unresolved conflict reported during policy combination (e.g. {@code MASK_CONFLICT}, {@code OBLIGATION_CONFLICT},
 * {@code ENF-GEN-019..020}).
 *
 * @param conflictKind conflict classification code
 * @param targetKey affected attributeId or obligationType
 * @param conflictingPolicyUnitKeys policy unit keys that produced the conflict
 * @param diagnosticMessage sanitized diagnostic description
 */
public record PolicyConflictIssue(
        String conflictKind,
        String targetKey,
        Set<String> conflictingPolicyUnitKeys,
        String diagnosticMessage
) {

    /** Validates non-blank conflict fields and normalizes conflicting unit keys. */
    public PolicyConflictIssue {
        conflictKind = requireNonBlank(conflictKind, "conflictKind");
        targetKey = requireNonBlank(targetKey, "targetKey");
        conflictingPolicyUnitKeys = conflictingPolicyUnitKeys == null ? Set.of() : Set.copyOf(conflictingPolicyUnitKeys);
        diagnosticMessage = requireNonBlank(diagnosticMessage, "diagnosticMessage");
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
