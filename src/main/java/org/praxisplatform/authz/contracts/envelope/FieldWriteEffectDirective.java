package org.praxisplatform.authz.contracts.envelope;

import java.util.Objects;

/**
 * Field-write effect directive for a specific canonical {@code attributeId}.
 *
 * @param attributeId canonical {@code @DomainLineage.attributeId}
 * @param effect {@code ALLOW} or {@code DENY}
 */
public record FieldWriteEffectDirective(
        String attributeId,
        RuleEffect effect
) {

    /** Validates non-blank attributeId and non-null effect. */
    public FieldWriteEffectDirective {
        Objects.requireNonNull(attributeId, "attributeId is required");
        attributeId = attributeId.trim();
        if (attributeId.isEmpty()) {
            throw new IllegalArgumentException("attributeId must not be blank");
        }
        effect = Objects.requireNonNull(effect, "effect is required");
    }
}
