package org.praxisplatform.authz.contracts.policy;

import java.util.Objects;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;

/**
 * {@code FIELD_WRITE} capability contribution inside {@link AuthorizationRuleContributions} ({@code CC01}).
 *
 * @param fieldSelector field selector targeting one or more attributes
 * @param effect {@code ALLOW} or {@code DENY}
 */
public record FieldWriteContributionSpec(
        PolicyFieldSelector fieldSelector,
        RuleEffect effect
) {

    /** Validates non-null selector and effect. */
    public FieldWriteContributionSpec {
        fieldSelector = Objects.requireNonNull(fieldSelector, "fieldSelector is required");
        effect = Objects.requireNonNull(effect, "effect is required");
    }
}
