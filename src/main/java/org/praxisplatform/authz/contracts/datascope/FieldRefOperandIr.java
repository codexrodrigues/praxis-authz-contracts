package org.praxisplatform.authz.contracts.datascope;

import java.util.Objects;

/**
 * Field-reference right-hand operand comparing two queryable resource fields ({@code DSP-AST-010}).
 *
 * @param targetFieldPath canonical {@code resource.*} field path
 * @param targetAttributeId canonical {@code @DomainLineage.attributeId}
 */
public record FieldRefOperandIr(
        String targetFieldPath,
        String targetAttributeId
) implements RightOperandIr {

    /** Validates canonical resource field path and attributeId. */
    public FieldRefOperandIr {
        Objects.requireNonNull(targetFieldPath, "targetFieldPath is required");
        targetFieldPath = targetFieldPath.trim();
        if (!targetFieldPath.startsWith("resource.")) {
            throw new IllegalArgumentException("targetFieldPath must start with 'resource.': " + targetFieldPath);
        }
        Objects.requireNonNull(targetAttributeId, "targetAttributeId is required");
        targetAttributeId = targetAttributeId.trim();
        if (targetAttributeId.isEmpty()) {
            throw new IllegalArgumentException("targetAttributeId must not be blank");
        }
    }
}
