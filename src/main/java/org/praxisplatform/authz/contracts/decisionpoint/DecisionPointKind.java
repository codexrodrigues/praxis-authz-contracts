package org.praxisplatform.authz.contracts.decisionpoint;

/**
 * Canonical decision point species ({@code DPC-KIND-001}).
 */
public enum DecisionPointKind {
    RESOURCE_OPERATION("resource-operation"),
    WORKFLOW_ACTION("workflow-action"),
    EXPLICIT_DECISION("explicit-decision");

    private final String keyPrefix;

    DecisionPointKind(String keyPrefix) {
        this.keyPrefix = keyPrefix;
    }

    /** Returns the canonical serialized key prefix for this kind ({@code DPC-ID-009}). */
    public String keyPrefix() {
        return keyPrefix;
    }
}
