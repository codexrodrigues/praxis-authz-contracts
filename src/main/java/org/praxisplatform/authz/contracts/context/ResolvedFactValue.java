package org.praxisplatform.authz.contracts.context;

import java.util.Objects;

/**
 * Resolved value and explicit 6-state status of a single fact inside an {@link EvaluationContextSnapshot}
 * ({@code CC04}, {@code CTX-RES-001..006}).
 *
 * @param factPath canonical SARC fact path
 * @param status explicit resolution status among the 6 frozen states
 * @param value resolved value (non-null iff {@code status == PRESENT})
 * @param unavailableCause explicit cause when {@code status == UNAVAILABLE}, otherwise {@link FactUnavailableCause#NONE}
 * @param diagnosticCode optional sanitized diagnostic code
 */
public record ResolvedFactValue(
        String factPath,
        FactResolutionStatus status,
        Object value,
        FactUnavailableCause unavailableCause,
        String diagnosticCode
) {

    /** Validates consistency between {@link FactResolutionStatus}, {@code value}, and {@link FactUnavailableCause}. */
    public ResolvedFactValue {
        factPath = requireNonBlank(factPath, "factPath");
        status = Objects.requireNonNull(status, "status is required");
        unavailableCause = unavailableCause == null ? FactUnavailableCause.NONE : unavailableCause;
        if (status == FactResolutionStatus.PRESENT) {
            if (value == null) {
                throw new IllegalArgumentException("PRESENT fact '" + factPath + "' must have a non-null value");
            }
            if (unavailableCause != FactUnavailableCause.NONE) {
                throw new IllegalArgumentException("PRESENT fact '" + factPath + "' must have unavailableCause=NONE");
            }
        } else {
            if (value != null) {
                throw new IllegalArgumentException(
                        "Non-PRESENT fact '" + factPath + "' (" + status + ") must not carry a non-null value");
            }
            if (status == FactResolutionStatus.UNAVAILABLE && unavailableCause == FactUnavailableCause.NONE) {
                throw new IllegalArgumentException(
                        "UNAVAILABLE fact '" + factPath + "' must specify a non-NONE FactUnavailableCause");
            }
            if (status != FactResolutionStatus.UNAVAILABLE && unavailableCause != FactUnavailableCause.NONE) {
                throw new IllegalArgumentException(
                        "Fact '" + factPath + "' with status=" + status + " must have unavailableCause=NONE");
            }
        }
    }

    /** Convenience factory for a {@link FactResolutionStatus#PRESENT} fact value. */
    public static ResolvedFactValue present(String factPath, Object value) {
        return new ResolvedFactValue(factPath, FactResolutionStatus.PRESENT, value, FactUnavailableCause.NONE, null);
    }

    /** Convenience factory for an explicit {@link FactResolutionStatus#NULL} fact value. */
    public static ResolvedFactValue explicitNull(String factPath) {
        return new ResolvedFactValue(factPath, FactResolutionStatus.NULL, null, FactUnavailableCause.NONE, null);
    }

    /** Convenience factory for a structurally {@link FactResolutionStatus#ABSENT} fact value. */
    public static ResolvedFactValue absent(String factPath) {
        return new ResolvedFactValue(factPath, FactResolutionStatus.ABSENT, null, FactUnavailableCause.NONE, null);
    }

    /** Convenience factory for a {@link FactResolutionStatus#STALE} fact value. */
    public static ResolvedFactValue stale(String factPath, String diagnosticCode) {
        return new ResolvedFactValue(factPath, FactResolutionStatus.STALE, null, FactUnavailableCause.NONE, diagnosticCode);
    }

    /** Convenience factory for an {@link FactResolutionStatus#UNAVAILABLE} fact value. */
    public static ResolvedFactValue unavailable(String factPath, FactUnavailableCause cause, String diagnosticCode) {
        return new ResolvedFactValue(factPath, FactResolutionStatus.UNAVAILABLE, null, cause, diagnosticCode);
    }

    /** Convenience factory for an {@link FactResolutionStatus#ERROR} fact value. */
    public static ResolvedFactValue error(String factPath, String diagnosticCode) {
        return new ResolvedFactValue(factPath, FactResolutionStatus.ERROR, null, FactUnavailableCause.NONE, diagnosticCode);
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
