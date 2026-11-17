package org.praxisplatform.authz.contracts.annotation;

/**
 * Row-level isolation and admission strategy declared via {@link AuthzTenantScope}.
 */
public enum AuthzTenantScopeMode {

    /**
     * Rows are isolated strictly by a single tenant identifier field on the resource
     * (e.g., {@code resource.tenantId == subject.tenantId}).
     */
    TENANT_ONLY,

    /**
     * Rows are hard-scoped by tenant/unit and dynamically filtered in OPA {@code DATA_SCOPE}
     * against the caller's authorized organizational units
     * (e.g., {@code resource.<field> in subject.organizationUnitIds}).
     */
    ORGANIZATIONAL_UNIT,

    /**
     * Shared catalog or reference resource accessible to any authenticated caller
     * ({@code subject.principalId != ""}) without per-tenant or per-organization row filtering.
     */
    AUTHENTICATED_SHARED
}
