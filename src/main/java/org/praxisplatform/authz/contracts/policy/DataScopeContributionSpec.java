package org.praxisplatform.authz.contracts.policy;

import java.util.Objects;
import org.praxisplatform.authz.contracts.envelope.ContributionAuthority;

/**
 * {@code DATA_SCOPE} capability contribution inside {@link AuthorizationRuleContributions}
 * ({@code CC01}, {@code PDP-EFF-003..004}, {@code PDP-CMB-004..005}).
 *
 * @param authority {@link ContributionAuthority#GRANT} (unioned into GrantSurface) or {@link ContributionAuthority#RESTRICT} (intersected as restriction)
 * @param resourceCondition condition governed by {@link ConditionProfileKind#AUTHORIZATION_SEARCH_SOURCE_V1}
 */
public record DataScopeContributionSpec(
        ContributionAuthority authority,
        AuthorizationSourceCondition resourceCondition
) {

    /** Validates authority and requires {@code authorization-search-source/v1} on {@code resourceCondition}. */
    public DataScopeContributionSpec {
        authority = Objects.requireNonNull(authority, "authority is required");
        resourceCondition = Objects.requireNonNull(resourceCondition, "resourceCondition is required");
        if (resourceCondition.profile() != ConditionProfileKind.AUTHORIZATION_SEARCH_SOURCE_V1) {
            throw new IllegalArgumentException(
                    "DataScopeContributionSpec resourceCondition must use profile AUTHORIZATION_SEARCH_SOURCE_V1");
        }
    }
}
