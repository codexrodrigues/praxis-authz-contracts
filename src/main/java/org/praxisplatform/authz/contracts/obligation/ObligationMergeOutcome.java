package org.praxisplatform.authz.contracts.obligation;

import java.util.Objects;
import org.praxisplatform.authz.contracts.envelope.ObligationDirective;

/**
 * Outcome of merging two {@link ObligationDirective}s ({@code CC10}).
 *
 * @param status merge status
 * @param mergedDirective merged directive when {@code status == MERGED}
 * @param diagnosticCode diagnostic code when merge fails
 */
public record ObligationMergeOutcome(
        ObligationMergeStatus status,
        ObligationDirective mergedDirective,
        String diagnosticCode
) {

    /** Validates consistency between {@link ObligationMergeStatus} and {@code mergedDirective}. */
    public ObligationMergeOutcome {
        status = Objects.requireNonNull(status, "status is required");
        if (status == ObligationMergeStatus.MERGED && mergedDirective == null) {
            throw new IllegalArgumentException("MERGED outcome must provide mergedDirective");
        }
        if (status != ObligationMergeStatus.MERGED
                && (diagnosticCode == null || diagnosticCode.isBlank())) {
            throw new IllegalArgumentException(status + " outcome must provide diagnosticCode");
        }
    }
}
