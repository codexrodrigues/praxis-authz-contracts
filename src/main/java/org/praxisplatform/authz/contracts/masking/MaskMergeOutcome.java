package org.praxisplatform.authz.contracts.masking;

import java.util.Objects;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;

/**
 * Outcome of merging two {@link MaskDirective}s in {@link MaskStrategyRegistry#merge(MaskDirective, MaskDirective)}
 * ({@code CC09}).
 *
 * @param status merge status
 * @param effectiveDirective merged directive when {@code status == MERGED}, otherwise {@code null}
 * @param conflictDiagnosticCode diagnostic code when {@code status == MASK_CONFLICT}
 */
public record MaskMergeOutcome(
        MaskMergeStatus status,
        MaskDirective effectiveDirective,
        String conflictDiagnosticCode
) {

    /** Validates consistency between {@link MaskMergeStatus} and {@code effectiveDirective}. */
    public MaskMergeOutcome {
        status = Objects.requireNonNull(status, "status is required");
        if (status == MaskMergeStatus.MERGED && effectiveDirective == null) {
            throw new IllegalArgumentException("MERGED outcome must provide effectiveDirective");
        }
        if (status == MaskMergeStatus.MASK_CONFLICT
                && (conflictDiagnosticCode == null || conflictDiagnosticCode.isBlank())) {
            throw new IllegalArgumentException("MASK_CONFLICT outcome must provide conflictDiagnosticCode");
        }
    }
}
