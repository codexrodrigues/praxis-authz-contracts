package org.praxisplatform.authz.contracts.datascope;

/**
 * Pushdown mode for {@link DataScopePlan} ({@code DSP-PUSH-001}).
 *
 * <p>Post-fetch in-memory page filtering is forbidden because it corrupts {@code totalElements},
 * pagination, {@code /stats/*}, and collection exports.</p>
 */
public enum PushdownMode {
    FULL_PUSHDOWN
}
