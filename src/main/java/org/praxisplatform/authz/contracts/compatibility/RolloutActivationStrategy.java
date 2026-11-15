package org.praxisplatform.authz.contracts.compatibility;

/**
 * Zero-downtime rollout activation strategy for a decision point ({@code CC08}, {@code OPA-HANDSHAKE-003}).
 */
public enum RolloutActivationStrategy {
    POLICY_FIRST,
    COORDINATED_ACTIVATION,
    HARD_DEFAULT
}
