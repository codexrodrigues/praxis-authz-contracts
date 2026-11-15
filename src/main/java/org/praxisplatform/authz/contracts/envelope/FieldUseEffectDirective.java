package org.praxisplatform.authz.contracts.envelope;

import java.util.Objects;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;

/**
 * Field-use effect directive for a specific canonical {@code attributeId} and {@link FieldUseCategory}.
 *
 * @param attributeId canonical {@code @DomainLineage.attributeId}
 * @param category field-use category ({@code VALUE}, {@code FILTER}, {@code SORT}, {@code GROUP}, {@code AGGREGATE}, {@code JOIN})
 * @param effect {@code ALLOW} or {@code DENY}
 */
public record FieldUseEffectDirective(
        String attributeId,
        FieldUseCategory category,
        RuleEffect effect
) {

    /** Validates non-blank attributeId and non-null category/effect. */
    public FieldUseEffectDirective {
        Objects.requireNonNull(attributeId, "attributeId is required");
        attributeId = attributeId.trim();
        if (attributeId.isEmpty()) {
            throw new IllegalArgumentException("attributeId must not be blank");
        }
        category = Objects.requireNonNull(category, "category is required");
        effect = Objects.requireNonNull(effect, "effect is required");
    }
}
