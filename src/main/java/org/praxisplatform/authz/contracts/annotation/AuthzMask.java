package org.praxisplatform.authz.contracts.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;

/**
 * Declares server-side detached DTO masking metadata ({@code CC09}) directly on a DTO field,
 * record component, accessor, or resource type.
 *
 * <p>Runtime frameworks translate this annotation into
 * {@link org.praxisplatform.authz.contracts.policy.MaskContributionSpec} directives during policy
 * bootstrap and validate compatibility against
 * {@link org.praxisplatform.authz.contracts.masking.MaskStrategyRegistry}. Note that
 * {@code FIELD_USE(VALUE) = DENY} always dominates any masking directive in the commutative lattice.</p>
 *
 * <pre>{@code
 *   @AuthzMask(
 *       strategy = AuthzMaskStrategy.REDACT_CONSTANT,
 *       replacement = "***CONFIDENTIAL***",
 *       reason = "Protected health diagnostic code"
 *   )
 *   private String medicalCode;
 * }</pre>
 *
 * @see AuthzMaskStrategy
 * @see AuthzMasks
 * @see org.praxisplatform.authz.contracts.masking.DefaultMaskStrategyRegistry
 */
@Target({ElementType.FIELD, ElementType.METHOD, ElementType.RECORD_COMPONENT, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Repeatable(AuthzMasks.class)
@Documented
public @interface AuthzMask {

    /**
     * Masking strategy to apply on detached DTO projections.
     *
     * @return masking strategy (defaults to {@link AuthzMaskStrategy#REDACT_CONSTANT})
     */
    AuthzMaskStrategy strategy() default AuthzMaskStrategy.REDACT_CONSTANT;

    /**
     * Explicit strategy identifier used when {@link #strategy()} is {@link AuthzMaskStrategy#CUSTOM}
     * (or when overriding a custom host registry entry).
     *
     * @return custom strategy identifier or blank
     */
    String customStrategyId() default "";

    /**
     * Canonical {@code @DomainLineage.attributeId} targeted by this mask. Optional when placed on a
     * DTO member (inferred from field/lineage metadata); required for {@link ElementType#TYPE}
     * declarations.
     *
     * @return attribute identifier or blank
     */
    String attributeId() default "";

    /**
     * Constant replacement string used by {@link AuthzMaskStrategy#REDACT_CONSTANT}.
     *
     * @return replacement placeholder (defaults to {@code "***"})
     */
    String replacement() default "***";

    /**
     * Number of leading characters kept visible by {@link AuthzMaskStrategy#PARTIAL_MASK}.
     *
     * @return visible prefix length (defaults to {@code 0})
     */
    int visiblePrefix() default 0;

    /**
     * Number of trailing characters kept visible by {@link AuthzMaskStrategy#PARTIAL_MASK}.
     *
     * @return visible suffix length (defaults to {@code 0})
     */
    int visibleSuffix() default 0;

    /**
     * Masking character used for obscured positions in {@link AuthzMaskStrategy#PARTIAL_MASK}.
     *
     * @return mask character string (defaults to {@code "*"})
     */
    String maskChar() default "*";

    /**
     * Key alias parameter passed to {@link AuthzMaskStrategy#HASH_TOKEN_KEYED}.
     *
     * @return key alias or blank
     */
    String keyAlias() default "";

    /**
     * Truncated token length passed to {@link AuthzMaskStrategy#HASH_TOKEN_KEYED}.
     *
     * @return truncated character count (defaults to {@code 16})
     */
    int truncateChars() default 16;

    /**
     * Format template passed to {@link AuthzMaskStrategy#SUMMARY_ONLY}.
     *
     * @return summary format or blank
     */
    String summaryFormat() default "";

    /**
     * Evaluation modes in which this masking directive should be materialized.
     *
     * @return evaluation modes (defaults to {@code {SEARCH, TARGET}})
     */
    EvaluationMode[] modes() default {EvaluationMode.SEARCH, EvaluationMode.TARGET};

    /**
     * Optional UI surface identifiers ({@code @UiSurface.id()}) to which this mask also applies.
     * When empty, host bootstrap policies may apply the mask across default resource and surface views.
     *
     * @return surface keys
     */
    String[] surfaces() default {};

    /**
     * Optional short human-readable rationale for auditability and policy readiness checks.
     *
     * @return rationale text
     */
    String reason() default "";
}
