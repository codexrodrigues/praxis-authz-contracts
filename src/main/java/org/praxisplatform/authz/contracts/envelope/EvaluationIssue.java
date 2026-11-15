package org.praxisplatform.authz.contracts.envelope;

import java.util.Objects;

/**
 * Diagnostic issue emitted during provider evaluation ({@code CC07}).
 *
 * @param issueCode machine-readable issue code
 * @param severity severity level (e.g. {@code ERROR}, {@code WARN})
 * @param factPath optional fact path associated with the issue
 * @param message sanitized diagnostic message
 */
public record EvaluationIssue(
        String issueCode,
        String severity,
        String factPath,
        String message
) {

    /** Validates required issue fields. */
    public EvaluationIssue {
        issueCode = requireNonBlank(issueCode, "issueCode");
        severity = requireNonBlank(severity, "severity");
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
