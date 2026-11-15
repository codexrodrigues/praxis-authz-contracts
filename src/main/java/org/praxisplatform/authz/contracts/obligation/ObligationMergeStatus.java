package org.praxisplatform.authz.contracts.obligation;

/**
 * Status of merging two {@link org.praxisplatform.authz.contracts.envelope.ObligationDirective}s
 * of the same type ({@code CC10}, {@code PCB-OBL-001..005}).
 */
public enum ObligationMergeStatus {
    MERGED,
    OBLIGATION_CONFLICT,
    UNKNOWN_OBLIGATION_TYPE
}
