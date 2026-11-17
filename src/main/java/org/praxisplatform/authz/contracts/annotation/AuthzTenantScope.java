package org.praxisplatform.authz.contracts.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declares the tenant and organizational row-level scope strategy for a governed resource.
 *
 * <p>May be placed on a domain entity, resource service, controller, or directly on the entity
 * field/accessor holding the tenant or organizational unit discriminator. Hosts using
 * {@code praxis-authz-starter} consume this metadata to automatically synthesize hard-scope
 * predicates, {@code DATA_SCOPE} OPA rules, and bulk-action scope bindings without manual
 * per-resource policy registration.</p>
 *
 * <pre>{@code
 *   @AuthzTenantScope(
 *       mode = AuthzTenantScopeMode.ORGANIZATIONAL_UNIT,
 *       tenantField = "organizationId",
 *       subjectFactPath = "subject.organizationUnitIds"
 *   )
 *   public class LeaveRequestEntity { ... }
 * }</pre>
 *
 * @see AuthzTenantScopeMode
 * @see AuthzScopeAnchor
 */
@Target({ElementType.TYPE, ElementType.FIELD, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface AuthzTenantScope {

    /**
     * Row-level isolation and admission mode for the governed resource.
     *
     * @return tenant scope mode (defaults to {@link AuthzTenantScopeMode#ORGANIZATIONAL_UNIT})
     */
    AuthzTenantScopeMode mode() default AuthzTenantScopeMode.ORGANIZATIONAL_UNIT;

    /**
     * Property path on the domain entity holding the tenant or organization hard-scope discriminator.
     * Ignored when {@link #mode()} is {@link AuthzTenantScopeMode#AUTHENTICATED_SHARED} unless an
     * explicit host hard-scope is also configured.
     *
     * @return entity field path (defaults to {@code "tenantId"})
     */
    String tenantField() default "tenantId";

    /**
     * Canonical {@code resource.*} SARC fact path evaluated inside generated OPA {@code DATA_SCOPE}
     * predicates (e.g., {@code "resource.organizationId"}). When blank, defaults to
     * {@code "resource." + tenantField()}.
     *
     * @return optional resource fact path override
     */
    String resourceFactPath() default "";

    /**
     * Canonical {@code subject.*} SARC fact path containing the caller's authoritative tenant or
     * organizational unit grants (e.g., {@code "subject.organizationUnitIds"} or
     * {@code "subject.tenantId"}).
     *
     * @return subject fact path (defaults to {@code "subject.organizationUnitIds"})
     */
    String subjectFactPath() default "subject.organizationUnitIds";

    /**
     * Optional explicit policy identifier used when materializing the primary scope policy.
     *
     * @return explicit policy ID or blank for convention-based generation
     */
    String policyId() default "";

    /**
     * Optional explicit primary rule identifier used when materializing the scope policy.
     *
     * @return explicit rule ID or blank for convention-based generation
     */
    String ruleId() default "";

    /**
     * Indicates whether collection-scoped bulk commands on an
     * {@link AuthzTenantScopeMode#AUTHENTICATED_SHARED} resource are allowed to materialize an
     * unconditional non-null data-scope check when no tenant/org filter applies.
     *
     * @return {@code true} if bulk actions may run over shared catalogs
     */
    boolean allowBulkWithoutScope() default false;

    /**
     * Optional queryable {@code resource.*} fact path used in {@code is_not_null} data-scope
     * predicates for shared-catalog bulk operations when {@link #allowBulkWithoutScope()} is
     * {@code true}.
     *
     * @return optional queryable resource fact path (e.g., {@code "resource.id"})
     */
    String sharedBulkNonNullFactPath() default "";
}
