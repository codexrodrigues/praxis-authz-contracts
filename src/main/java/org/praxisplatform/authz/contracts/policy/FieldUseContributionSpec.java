package org.praxisplatform.authz.contracts.policy;

import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;

/**
 * {@code FIELD_USE} capability contribution inside {@link AuthorizationRuleContributions} ({@code CC01}).
 *
 * @param fieldSelector field selector targeting one or more attributes
 * @param categories non-empty set of {@link FieldUseCategory} values ({@code VALUE}, {@code FILTER}, {@code SORT}, {@code GROUP}, {@code AGGREGATE}, {@code JOIN})
 * @param effect {@code ALLOW} or {@code DENY}
 */
public record FieldUseContributionSpec(
        PolicyFieldSelector fieldSelector,
        Set<FieldUseCategory> categories,
        RuleEffect effect
) {

    /** Validates non-null selector, non-empty categories, and effect. */
    public FieldUseContributionSpec {
        fieldSelector = Objects.requireNonNull(fieldSelector, "fieldSelector is required");
        Objects.requireNonNull(categories, "categories is required");
        if (categories.isEmpty()) {
            throw new IllegalArgumentException("categories must not be empty");
        }
        categories = Set.copyOf(categories);
        effect = Objects.requireNonNull(effect, "effect is required");
    }
}
