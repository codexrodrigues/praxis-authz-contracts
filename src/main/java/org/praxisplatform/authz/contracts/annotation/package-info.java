/**
 * Framework-neutral declarative authorization annotations for Praxis Platform resources, DTOs,
 * workflow actions, and UI surfaces ({@code CC01}, {@code CC03}, {@code CC06}, {@code CC09}).
 *
 * <p>All annotations in this package depend strictly on the Java SE standard library and pure
 * {@code praxis-authz-contracts} types (zero Spring, JPA, Hibernate, or Jackson dependencies).
 * Runtime frameworks such as {@code praxis-authz-starter} introspect these annotations to
 * synthesize {@link org.praxisplatform.authz.contracts.policy.AuthorizationPolicyDefinition}s,
 * {@link org.praxisplatform.authz.contracts.policy.DualScopeDelegationSpec}s, masking rules,
 * mandatory scope anchors, and tenant/organizational data scopes without host boilerplate.</p>
 */
package org.praxisplatform.authz.contracts.annotation;
