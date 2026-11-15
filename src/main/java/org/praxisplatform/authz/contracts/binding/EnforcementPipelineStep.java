package org.praxisplatform.authz.contracts.binding;

/**
 * Invariant 15-step execution pipeline defined by {@code enforcement-contract-spec-r3.md} §46 ({@code ENF-PIPE-001..015}).
 */
public enum EnforcementPipelineStep {
    STEP_01_RESOLVE_POINT_AND_READINESS(1, HostEnforcementPhase.ADMISSION),
    STEP_02_EXTRACT_ADMISSION_AND_WRITE_INTENT(2, HostEnforcementPhase.ADMISSION),
    STEP_03_GUARD_QUERY_FIELD_USE(3, HostEnforcementPhase.REQUEST_QUERY),
    STEP_04_EVALUATE_ADMISSION_OR_SEARCH_PROVIDER(4, HostEnforcementPhase.ADMISSION),
    STEP_05_NORMALIZE_ADMISSION_DECISION(5, HostEnforcementPhase.ADMISSION),
    STEP_06_FULFILL_BEFORE_EXECUTION_OBLIGATIONS(6, HostEnforcementPhase.ADMISSION),
    STEP_07_INJECT_DATA_SCOPE_PLAN(7, HostEnforcementPhase.REQUEST_QUERY),
    STEP_08_RESOLVE_TARGET_ENTITY_WITHIN_SCOPE(8, HostEnforcementPhase.TARGET_RESOLUTION),
    STEP_09_COMPOSE_TARGET_CONTEXT_SNAPSHOT(9, HostEnforcementPhase.TARGET_RESOLUTION),
    STEP_10_EVALUATE_TARGET_PROVIDER_AND_NORMALIZE(10, HostEnforcementPhase.PRE_MUTATION),
    STEP_11_ENFORCE_PRE_MUTATION_ACCESS_AND_FIELD_WRITE(11, HostEnforcementPhase.PRE_MUTATION),
    STEP_12_EXECUTE_SERVER_HYDRATION_AND_BUSINESS_RULES(12, HostEnforcementPhase.PRE_MUTATION),
    STEP_13_PERSIST_MUTATION_AND_DOMAIN_HOOKS(13, HostEnforcementPhase.PRE_COMMIT_OUTBOX),
    STEP_14_FULFILL_BEFORE_COMMIT_OUTBOX_OBLIGATIONS(14, HostEnforcementPhase.PRE_COMMIT_OUTBOX),
    STEP_15_DETACHED_PROJECTION_MASK_AND_DISCLOSURE(15, HostEnforcementPhase.PRE_DISCLOSURE);

    private final int stepNumber;
    private final HostEnforcementPhase phase;

    EnforcementPipelineStep(int stepNumber, HostEnforcementPhase phase) {
        this.stepNumber = stepNumber;
        this.phase = phase;
    }

    /** Returns the 1-based ordinal step number (1..15). */
    public int stepNumber() {
        return stepNumber;
    }

    /** Returns the canonical host enforcement phase associated with this step. */
    public HostEnforcementPhase phase() {
        return phase;
    }
}
