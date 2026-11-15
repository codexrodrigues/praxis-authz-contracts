package org.praxisplatform.authz.contracts.decisionpoint;

/**
 * Distinguishes domain business decisions ({@code praxis-rules-engine}) from authorization decisions
 * ({@code praxis-authz-*}).
 */
public enum DecisionKind {
    BUSINESS,
    AUTHORIZATION
}
