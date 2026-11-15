package org.praxisplatform.authz.contracts.policy;

/**
 * Deterministic {@code praxis-json-logic} condition profile kind ({@code CC02}, {@code PDP-COND-001}).
 */
public enum ConditionProfileKind {
    AUTHORIZATION_TARGET_V1("authorization-target/v1"),
    AUTHORIZATION_SEARCH_SOURCE_V1("authorization-search-source/v1");

    private final String profileId;

    ConditionProfileKind(String profileId) {
        this.profileId = profileId;
    }

    /** Returns the canonical wire profile identifier. */
    public String profileId() {
        return profileId;
    }
}
