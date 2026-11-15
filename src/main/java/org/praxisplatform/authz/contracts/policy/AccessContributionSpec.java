package org.praxisplatform.authz.contracts.policy;

import java.util.Objects;
import org.praxisplatform.authz.contracts.envelope.ContributionAuthority;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;

/**
 * {@code ACCESS} capability contribution inside {@link AuthorizationRuleContributions} ({@code CC01}).
 *
 * @param authority {@link ContributionAuthority#GRANT} or {@link ContributionAuthority#RESTRICT}
 * @param effect {@link RuleEffect#ALLOW} or {@link RuleEffect#DENY}
 */
public record AccessContributionSpec(
        ContributionAuthority authority,
        RuleEffect effect
) {

    /** Validates authority/effect coherence ({@code GRANT} pairs with {@code ALLOW}; {@code RESTRICT} pairs with {@code DENY}). */
    public AccessContributionSpec {
        authority = Objects.requireNonNull(authority, "authority is required");
        effect = Objects.requireNonNull(effect, "effect is required");
        if (authority == ContributionAuthority.GRANT && effect != RuleEffect.ALLOW) {
            throw new IllegalArgumentException("AccessContributionSpec with authority=GRANT must have effect=ALLOW");
        }
        if (authority == ContributionAuthority.RESTRICT && effect != RuleEffect.DENY) {
            throw new IllegalArgumentException("AccessContributionSpec with authority=RESTRICT must have effect=DENY");
        }
    }
}
