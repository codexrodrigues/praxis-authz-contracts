package org.praxisplatform.authz.contracts.policy;

import java.util.Objects;

/**
 * Structured diagnostic emitted by {@link AuthorizationPolicyCandidateValidator} ({@code CC02}).
 *
 * @param code machine-readable diagnostic code
 * @param severity severity ({@code ERROR} or {@code WARN})
 * @param ruleId optional rule identifier
 * @param jsonPointer JSON Pointer locating the offending element
 * @param message actionable diagnostic message
 */
public record PolicyValidationDiagnostic(
        String code,
        String severity,
        String ruleId,
        String jsonPointer,
        String message
) {

    /** Validates required diagnostic fields. */
    public PolicyValidationDiagnostic {
        code = requireNonBlank(code, "code");
        severity = requireNonBlank(severity, "severity");
        jsonPointer = requireNonBlank(jsonPointer, "jsonPointer");
        message = requireNonBlank(message, "message");
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
