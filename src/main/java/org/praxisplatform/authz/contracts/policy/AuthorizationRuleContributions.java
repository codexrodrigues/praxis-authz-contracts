package org.praxisplatform.authz.contracts.policy;

import java.util.List;
import java.util.Objects;

/**
 * Groups the 5 primary capability contributions ({@code ACCESS}, {@code DATA_SCOPE}, {@code FIELD_USE},
 * {@code FIELD_WRITE}, {@code MASK}) of an {@link AuthorizationPolicyRule} ({@code CC01}, {@code PDP-EFF-001..011}).
 *
 * <p>Per {@code PDP-EFF-009..011}, {@code obligations[]} is modeled as a sibling list on
 * {@link AuthorizationPolicyRule}, not nested inside capability contributions.</p>
 *
 * @param access optional {@code ACCESS} contribution
 * @param dataScope optional {@code DATA_SCOPE} contribution
 * @param fieldUse list of {@code FIELD_USE} contributions
 * @param fieldWrite list of {@code FIELD_WRITE} contributions
 * @param mask list of {@code MASK} contributions
 * @param reasonCode semantic reason code for audit and diagnostics
 */
public record AuthorizationRuleContributions(
        AccessContributionSpec access,
        DataScopeContributionSpec dataScope,
        List<FieldUseContributionSpec> fieldUse,
        List<FieldWriteContributionSpec> fieldWrite,
        List<MaskContributionSpec> mask,
        String reasonCode
) {

    /** Validates that at least one primary capability contribution is present and reasonCode is non-blank. */
    public AuthorizationRuleContributions {
        fieldUse = fieldUse == null ? List.of() : List.copyOf(fieldUse);
        fieldWrite = fieldWrite == null ? List.of() : List.copyOf(fieldWrite);
        mask = mask == null ? List.of() : List.copyOf(mask);
        if (access == null && dataScope == null
                && fieldUse.isEmpty() && fieldWrite.isEmpty() && mask.isEmpty()) {
            throw new IllegalArgumentException(
                    "AuthorizationRuleContributions must declare at least one capability contribution");
        }
        Objects.requireNonNull(reasonCode, "reasonCode is required");
        reasonCode = reasonCode.trim();
        if (reasonCode.isEmpty()) {
            throw new IllegalArgumentException("reasonCode must not be blank");
        }
    }
}
