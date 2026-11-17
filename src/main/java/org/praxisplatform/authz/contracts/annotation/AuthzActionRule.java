package org.praxisplatform.authz.contracts.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;

/**
 * Declares policy admission, condition, field-write grants, and audit metadata for a workflow
 * action, bulk domain command, or UI surface ({@code CC01}, {@code CC05}, {@code CC06}, {@code CC10}).
 *
 * <p>May be placed directly on a controller/service method alongside {@code @WorkflowAction} or
 * {@code @UiSurface}, or declared repetitively at {@link ElementType#TYPE} level to override or
 * enrich generated action/surface policies without manual bootstrap configuration.</p>
 *
 * <pre>{@code
 *   @AuthzActionRule(
 *       actionKey = "approve-progression",
 *       ruleId = "rule-approve-progression-item",
 *       conditionFactPath = "resource.candidateStatus",
 *       conditionAllowedValues = {"ELIGIBLE"},
 *       allowedWriteAttributes = {"hr.progressions.status", "hr.progressions.approved_at"}
 *   )
 * }</pre>
 *
 * @see AuthzActionRules
 * @see org.praxisplatform.authz.contracts.policy.AuthorizationPolicyDefinition
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Repeatable(AuthzActionRules.class)
@Documented
public @interface AuthzActionRule {

    /**
     * Canonical workflow action key ({@code @WorkflowAction.id()}). Optional when placed directly
     * on a method annotated with {@code @WorkflowAction} or when {@link #surfaceKey()} is used.
     *
     * @return action key or blank
     */
    String actionKey() default "";

    /**
     * Canonical UI surface key ({@code @UiSurface.id()}) when declaring a rule for a surface
     * decision point rather than a workflow action.
     *
     * @return surface key or blank
     */
    String surfaceKey() default "";

    /**
     * Optional explicit rule identifier (e.g., {@code "rule-approve-progression-item"}).
     * When blank, a deterministic rule ID is derived from the resource and action/surface key.
     *
     * @return rule identifier or blank
     */
    String ruleId() default "";

    /**
     * Optional explicit policy identifier override. When blank, a deterministic policy ID is
     * derived from the service, resource, and action/surface key.
     *
     * @return policy identifier or blank
     */
    String policyId() default "";

    /**
     * Evaluation modes covered by this rule. When empty, defaults are derived from the target
     * decision point ({@code TARGET} for item actions/surfaces; {@code SEARCH} + {@code TARGET}
     * for collection bulk commands).
     *
     * @return evaluation modes
     */
    EvaluationMode[] evaluationModes() default {};

    /**
     * Whether an authenticated non-blank {@code subject.principalId} is required by default.
     *
     * @return {@code true} by default
     */
    boolean requireAuthenticatedPrincipal() default true;

    /**
     * Optional subject roles/authorities required in {@code subject.roles} for admission.
     *
     * @return required role names
     */
    String[] requiredRoles() default {};

    /**
     * Optional canonical SARC fact path compared against {@link #conditionAllowedValues()} to
     * generate a structured condition without raw JSON-Logic strings
     * (e.g., {@code "resource.candidateStatus"}).
     *
     * @return fact path or blank
     */
    String conditionFactPath() default "";

    /**
     * Allowed literal values for {@link #conditionFactPath()} (single value compiles to {@code ==};
     * multiple values compile to {@code in}).
     *
     * @return allowed literal values
     */
    String[] conditionAllowedValues() default {};

    /**
     * Optional raw {@code praxis-json-logic} condition expression encoded as a JSON object string
     * for advanced predicates (e.g., {@code "{\"==\":[{\"var\":\"resource.status\"},\"OPEN\"]}"}).
     * Takes precedence over {@link #conditionFactPath()} when non-blank.
     *
     * @return JSON-Logic expression string or blank
     */
    String conditionJsonLogic() default "";

    /**
     * Canonical {@code attributeId}s explicitly granted {@code FIELD_WRITE = ALLOW} when this
     * action rule permits execution.
     *
     * @return writable attribute IDs
     */
    String[] allowedWriteAttributes() default {};

    /**
     * Optional deterministic {@code reasonCode} recorded in {@code DecisionEvidence}.
     *
     * @return reason code or blank for convention-based generation
     */
    String reasonCode() default "";

    /**
     * Whether {@code DURABLE_AUDIT_EVIDENCE} ({@code BEFORE_COMMIT_OUTBOX}) is attached to this
     * rule.
     *
     * @return {@code true} by default
     */
    boolean auditRequired() default true;

    /**
     * Optional {@code auditCategory} parameter recorded in the {@code DURABLE_AUDIT_EVIDENCE}
     * obligation directive.
     *
     * @return audit category or blank
     */
    String auditCategory() default "";

    /**
     * Optional {@code LegalTreatmentPurpose} override (must match one of
     * {@link org.praxisplatform.authz.contracts.context.FactDescriptor#ALLOWED_LEGAL_PURPOSES} when
     * non-blank).
     *
     * @return legal purpose name or blank
     */
    String legalPurpose() default "";

    /**
     * Optional statutory/regulatory reference backing {@link #legalPurpose()}
     * (e.g., {@code "LGPD:ART_7_III"}).
     *
     * @return legal basis reference or blank
     */
    String legalBasisRef() default "";

    /**
     * Optional human-readable description for policy governance catalogs and audit trails.
     *
     * @return rule description
     */
    String description() default "";
}
