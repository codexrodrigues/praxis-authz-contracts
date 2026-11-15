package org.praxisplatform.authz.contracts.masking;

/**
 * Status of merging two {@link org.praxisplatform.authz.contracts.envelope.MaskDirective}s in the
 * algebraic masking lattice ({@code CC09}, {@code PCB-MASK-001..005}).
 */
public enum MaskMergeStatus {
    MERGED,
    DOMINATED_BY_FIELD_USE_DENY,
    MASK_CONFLICT
}
