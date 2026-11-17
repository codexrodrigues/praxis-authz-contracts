package org.praxisplatform.authz.contracts.annotation;

import org.praxisplatform.authz.contracts.policy.DualScopeDelegationSpec;

/**
 * Canonical delegation split modes corresponding 1:1 to {@link DualScopeDelegationSpec} constants.
 */
public enum AuthzDelegationSplitMode {

    /**
     * Both origin and destination scopes may mutate their respective disjoint field partitions.
     *
     * @see DualScopeDelegationSpec#ORIGIN_DESTINATION_SPLIT
     */
    ORIGIN_DESTINATION_SPLIT(DualScopeDelegationSpec.ORIGIN_DESTINATION_SPLIT),

    /**
     * Only callers with origin custody may mutate attributes; destination-only callers are rejected.
     *
     * @see DualScopeDelegationSpec#ORIGIN_ONLY_WRITE
     */
    ORIGIN_ONLY_WRITE(DualScopeDelegationSpec.ORIGIN_ONLY_WRITE),

    /**
     * Destination callers have read-only access; mutations require origin custody.
     *
     * @see DualScopeDelegationSpec#READ_ONLY_DESTINATION
     */
    READ_ONLY_DESTINATION(DualScopeDelegationSpec.READ_ONLY_DESTINATION);

    private final String modeId;

    AuthzDelegationSplitMode(String modeId) {
        this.modeId = modeId;
    }

    /**
     * Canonical mode string published in {@link DualScopeDelegationSpec#mode()}.
     *
     * @return canonical mode identifier
     */
    public String modeId() {
        return modeId;
    }

    /**
     * Returns {@code true} when destination custody callers may mutate destination-partition fields.
     *
     * @return {@code true} only for {@link #ORIGIN_DESTINATION_SPLIT}
     */
    public boolean allowsDestinationWrites() {
        return this == ORIGIN_DESTINATION_SPLIT;
    }
}
