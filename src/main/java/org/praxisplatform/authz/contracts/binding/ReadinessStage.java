package org.praxisplatform.authz.contracts.binding;

/**
 * Four mandatory readiness stages required before a decision point enters authoritative execution
 * ({@code ENF-READY-001..004}).
 */
public enum ReadinessStage {
    STRUCTURAL_READY,
    POLICY_READY,
    PROVIDER_READY,
    ENFORCEMENT_READY
}
