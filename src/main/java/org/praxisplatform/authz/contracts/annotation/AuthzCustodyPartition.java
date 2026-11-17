package org.praxisplatform.authz.contracts.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declaratively specifies dual-scope custody partitioning ({@link org.praxisplatform.authz.contracts.policy.DualScopeDelegationSpec})
 * between an authoritative {@code ORIGIN} scope and a delegated {@code DESTINATION} scope
 * ({@code CC01}, {@code CC06}, {@code P17}, {@code PDP-SEM-004}).
 *
 * <p>Supports two complementary declarative styles:</p>
 * <ul>
 *   <li><b>Type-level declaration</b> (on a domain entity, service, or controller) specifying
 *       {@link #mode()}, origin/destination entity fields, fact paths, subject grant facts, and
 *       disjoint write attribute sets;</li>
 *   <li><b>Member-level declaration</b> (on DTO or entity fields/record components/accessors)
 *       assigning individual attributes to {@link AuthzCustodyRole#ORIGIN} or
 *       {@link AuthzCustodyRole#DESTINATION}, or marking a custody anchor field with
 *       {@link #custodyAnchor()} {@code = true} and {@link #subjectFactPath()}.</li>
 * </ul>
 *
 * <pre>{@code
 *   @AuthzCustodyPartition(
 *       mode = AuthzDelegationSplitMode.ORIGIN_DESTINATION_SPLIT,
 *       originEntityField = "originOrgId",
 *       originFactPath = "resource.originOrgId",
 *       originSubjectFactKey = "subject.organizationUnitIds",
 *       destinationEntityField = "destinationOrgId",
 *       destinationFactPath = "resource.destinationOrgId",
 *       destinationSubjectFactKey = "subject.delegatedDestinationOrgIds",
 *       originExclusiveWriteAttributes = {"hr.transfers.start_date"},
 *       destinationAllowedWriteAttributes = {"hr.transfers.local_supervisor"}
 *   )
 *   public class AssignmentTransferEntity { ... }
 * }</pre>
 *
 * @see AuthzDelegationSplitMode
 * @see AuthzCustodyRole
 * @see org.praxisplatform.authz.contracts.policy.DualScopeDelegationSpec
 */
@Target({ElementType.TYPE, ElementType.FIELD, ElementType.METHOD, ElementType.RECORD_COMPONENT})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface AuthzCustodyPartition {

    /**
     * Split-custody write authorization mode governing origin vs destination callers.
     *
     * @return delegation split mode (defaults to {@link AuthzDelegationSplitMode#ORIGIN_DESTINATION_SPLIT})
     */
    AuthzDelegationSplitMode mode() default AuthzDelegationSplitMode.ORIGIN_DESTINATION_SPLIT;

    /**
     * Custody party role when this annotation is applied directly to a field, record component, or
     * accessor. Ignored or left {@link AuthzCustodyRole#UNSPECIFIED} for type-level declarations.
     *
     * @return custody role (defaults to {@link AuthzCustodyRole#UNSPECIFIED})
     */
    AuthzCustodyRole role() default AuthzCustodyRole.UNSPECIFIED;

    /**
     * Entity field path holding the origin scope identifier (e.g., {@code "originOrgId"}).
     *
     * @return origin entity field path or blank
     */
    String originEntityField() default "";

    /**
     * Canonical {@code resource.*} SARC fact path for the origin scope
     * (e.g., {@code "resource.originOrgId"}).
     *
     * @return origin resource fact path or blank
     */
    String originFactPath() default "";

    /**
     * Canonical {@code subject.*} fact key holding the caller's authorized origin units
     * (e.g., {@code "subject.organizationUnitIds"}).
     *
     * @return origin subject fact key or blank
     */
    String originSubjectFactKey() default "";

    /**
     * Entity field path holding the delegated destination scope identifier
     * (e.g., {@code "destinationOrgId"}).
     *
     * @return destination entity field path or blank
     */
    String destinationEntityField() default "";

    /**
     * Canonical {@code resource.*} SARC fact path for the delegated destination scope
     * (e.g., {@code "resource.destinationOrgId"}).
     *
     * @return destination resource fact path or blank
     */
    String destinationFactPath() default "";

    /**
     * Canonical {@code subject.*} fact key holding the caller's delegated destination units
     * (e.g., {@code "subject.delegatedDestinationOrgIds"}).
     *
     * @return destination subject fact key or blank
     */
    String destinationSubjectFactKey() default "";

    /**
     * Canonical {@code attributeId}s writable exclusively by callers holding origin custody.
     * Must be disjoint from {@link #destinationAllowedWriteAttributes()}.
     *
     * @return origin-exclusive write attribute IDs
     */
    String[] originExclusiveWriteAttributes() default {};

    /**
     * Canonical {@code attributeId}s writable by callers holding destination custody when
     * {@link #mode()} is {@link AuthzDelegationSplitMode#ORIGIN_DESTINATION_SPLIT}. Must be
     * disjoint from {@link #originExclusiveWriteAttributes()}.
     *
     * @return destination-allowed write attribute IDs
     */
    String[] destinationAllowedWriteAttributes() default {};

    /**
     * Optional canonical {@code @DomainLineage.attributeId} override when placed on a field or
     * accessor whose lineage should be bound explicitly to a write partition.
     *
     * @return attribute identifier or blank to infer from DTO/entity metadata
     */
    String attributeId() default "";

    /**
     * Marks a member-level field as the custody discriminator anchor for {@link #role()} (matched
     * against {@link #subjectFactPath()}), rather than an editable business payload field.
     *
     * @return {@code true} when this field identifies the origin or destination custody unit
     */
    boolean custodyAnchor() default false;

    /**
     * Canonical {@code subject.*} fact path used with member-level {@link #custodyAnchor()}
     * {@code = true} declarations (e.g., {@code "subject.delegatedDestinationOrgIds"}).
     *
     * @return subject fact path or blank
     */
    String subjectFactPath() default "";
}
