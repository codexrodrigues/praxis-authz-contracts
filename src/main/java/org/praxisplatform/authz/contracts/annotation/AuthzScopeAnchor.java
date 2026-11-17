package org.praxisplatform.authz.contracts.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a field, record component, accessor, or resource type attribute as a mandatory
 * authorization scope anchor ({@code CC06}, {@code P14}).
 *
 * <p>Mandatory scope anchors cannot be omitted during {@code CREATE} operations, explicitly
 * cleared to {@code null} ({@code CLEAR_EXPLICIT_NULL}) during partial {@code PATCH} updates, or
 * removed ({@code REMOVE}) during full-replacement {@code PUT} requests.</p>
 *
 * <pre>{@code
 *   @AuthzScopeAnchor(reason = "Origin organization anchors row-level custody and tenant isolation")
 *   private Long originOrganizationId;
 * }</pre>
 *
 * @see AuthzScopeAnchors
 * @see AuthzTenantScope
 * @see AuthzCustodyPartition
 */
@Target({ElementType.FIELD, ElementType.METHOD, ElementType.RECORD_COMPONENT, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Repeatable(AuthzScopeAnchors.class)
@Documented
public @interface AuthzScopeAnchor {

    /**
     * Canonical {@code @DomainLineage.attributeId} of the scope anchor attribute. Optional when
     * placed directly on a DTO/entity field whose lineage or naming identifies the attribute;
     * required when declared at {@link ElementType#TYPE} level.
     *
     * @return canonical attribute identifier or blank to infer from the annotated member
     */
    String attributeId() default "";

    /**
     * Optional canonical {@code resource.*} SARC fact path associated with this anchor
     * (e.g., {@code "resource.originOrganizationId"}).
     *
     * @return canonical resource fact path or blank
     */
    String factPath() default "";

    /**
     * Whether omitting this anchor attribute in a {@code CREATE} payload must be rejected fail-closed.
     *
     * @return {@code true} by default
     */
    boolean requiredOnCreate() default true;

    /**
     * Whether clearing this anchor attribute ({@code CLEAR_EXPLICIT_NULL} or {@code REMOVE}) in an
     * update payload must be rejected fail-closed.
     *
     * @return {@code true} by default
     */
    boolean forbidClearOnUpdate() default true;

    /**
     * Whether mutating this anchor attribute to a different non-null value after creation is
     * forbidden unless performed by a dedicated transfer workflow with dual custody.
     *
     * @return {@code true} if the anchor is immutable after creation
     */
    boolean immutableAfterCreate() default false;

    /**
     * Optional short human-readable explanation recorded in readiness diagnostics and audit logs.
     *
     * @return audit/diagnostic reason
     */
    String reason() default "";
}
