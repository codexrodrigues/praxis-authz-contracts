package org.praxisplatform.authz.contracts.context;

/**
 * Canonical SARC top-level namespace for authorization facts ({@code subject.*}, {@code action.*},
 * {@code resource.*}, {@code context.*}).
 */
public enum FactSlotNamespace {
    SUBJECT("subject."),
    ACTION("action."),
    RESOURCE("resource."),
    CONTEXT("context.");

    private final String prefix;

    FactSlotNamespace(String prefix) {
        this.prefix = prefix;
    }

    /** Returns the required canonical path prefix for this namespace. */
    public String prefix() {
        return prefix;
    }
}
