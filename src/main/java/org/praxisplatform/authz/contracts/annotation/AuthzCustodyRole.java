package org.praxisplatform.authz.contracts.annotation;

/**
 * Custody party role used by field-level {@link AuthzCustodyPartition} declarations.
 */
public enum AuthzCustodyRole {

    /**
     * Unspecified role (typical for type-level {@link AuthzCustodyPartition} declarations that specify
     * origin and destination partitions jointly).
     */
    UNSPECIFIED,

    /**
     * Authoritative origin custody partition (owns record creation, structural attributes, and
     * origin-exclusive mutations).
     */
    ORIGIN,

    /**
     * Delegated destination custody partition (receiving unit granted read visibility and, when
     * permitted by {@link AuthzDelegationSplitMode#ORIGIN_DESTINATION_SPLIT}, mutations on
     * designated destination attributes).
     */
    DESTINATION
}
