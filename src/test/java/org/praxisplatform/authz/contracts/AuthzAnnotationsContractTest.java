package org.praxisplatform.authz.contracts;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.annotation.Annotation;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.contracts.annotation.AuthzActionRule;
import org.praxisplatform.authz.contracts.annotation.AuthzActionRules;
import org.praxisplatform.authz.contracts.annotation.AuthzCustodyPartition;
import org.praxisplatform.authz.contracts.annotation.AuthzCustodyRole;
import org.praxisplatform.authz.contracts.annotation.AuthzDelegationSplitMode;
import org.praxisplatform.authz.contracts.annotation.AuthzMask;
import org.praxisplatform.authz.contracts.annotation.AuthzMaskStrategy;
import org.praxisplatform.authz.contracts.annotation.AuthzMasks;
import org.praxisplatform.authz.contracts.annotation.AuthzScopeAnchor;
import org.praxisplatform.authz.contracts.annotation.AuthzScopeAnchors;
import org.praxisplatform.authz.contracts.annotation.AuthzTenantScope;
import org.praxisplatform.authz.contracts.annotation.AuthzTenantScopeMode;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.masking.DefaultMaskStrategyRegistry;
import org.praxisplatform.authz.contracts.masking.MaskStrategyDescriptor;
import org.praxisplatform.authz.contracts.policy.DualScopeDelegationSpec;

/**
 * Contract tests for pure Java declarative authorization annotations under
 * {@code org.praxisplatform.authz.contracts.annotation}.
 */
class AuthzAnnotationsContractTest {

    @AuthzTenantScope(
            mode = AuthzTenantScopeMode.ORGANIZATIONAL_UNIT,
            tenantField = "organizationId",
            resourceFactPath = "resource.organizationId",
            subjectFactPath = "subject.organizationUnitIds",
            policyId = "pol-hr-transfers",
            ruleId = "rule-hr-transfers-org-scope"
    )
    @AuthzCustodyPartition(
            mode = AuthzDelegationSplitMode.ORIGIN_DESTINATION_SPLIT,
            originEntityField = "originOrgId",
            originFactPath = "resource.originOrgId",
            originSubjectFactKey = "subject.organizationUnitIds",
            destinationEntityField = "destinationOrgId",
            destinationFactPath = "resource.destinationOrgId",
            destinationSubjectFactKey = "subject.delegatedDestinationOrgIds",
            originExclusiveWriteAttributes = {"hr.transfers.start_date"},
            destinationAllowedWriteAttributes = {"hr.transfers.local_notes"}
    )
    @AuthzScopeAnchor(attributeId = "hr.transfers.origin_org_id", factPath = "resource.originOrgId")
    @AuthzScopeAnchor(attributeId = "hr.transfers.destination_org_id", factPath = "resource.destinationOrgId")
    @AuthzActionRule(
            surfaceKey = "detail",
            ruleId = "rule-transfers-detail-surface",
            auditCategory = "GOVERNED_SURFACE_ACCESS"
    )
    @AuthzActionRule(
            actionKey = "reconcile-batch",
            ruleId = "rule-transfers-reconcile-bulk",
            evaluationModes = {EvaluationMode.SEARCH, EvaluationMode.TARGET}
    )
    static class SampleTransferResource {

        @AuthzScopeAnchor(immutableAfterCreate = true, reason = "Origin organization anchor")
        @AuthzCustodyPartition(
                role = AuthzCustodyRole.ORIGIN,
                custodyAnchor = true,
                subjectFactPath = "subject.organizationUnitIds"
        )
        private Long originOrgId;

        @AuthzCustodyPartition(
                role = AuthzCustodyRole.DESTINATION,
                custodyAnchor = true,
                subjectFactPath = "subject.delegatedDestinationOrgIds"
        )
        private Long destinationOrgId;

        @AuthzMask(
                strategy = AuthzMaskStrategy.REDACT_CONSTANT,
                replacement = "***CONFIDENTIAL***",
                surfaces = {"detail"},
                reason = "Restricted medical code"
        )
        @AuthzMask(
                strategy = AuthzMaskStrategy.PARTIAL_MASK,
                visiblePrefix = 1,
                visibleSuffix = 1,
                modes = {EvaluationMode.SEARCH}
        )
        private String medicalCode;

        @AuthzCustodyPartition(role = AuthzCustodyRole.DESTINATION, attributeId = "hr.transfers.local_notes")
        private String localNotes;

        @AuthzActionRule(
                actionKey = "approve",
                ruleId = "rule-approve-transfer",
                requiredRoles = {"HR_APPROVER"},
                conditionFactPath = "resource.status",
                conditionAllowedValues = {"PENDING_APPROVAL"},
                allowedWriteAttributes = {"hr.transfers.status", "hr.transfers.approved_at"},
                reasonCode = "ALLOW_TRANSFER_APPROVE"
        )
        public void approve() {
        }
    }

    @AuthzTenantScope(
            mode = AuthzTenantScopeMode.AUTHENTICATED_SHARED,
            allowBulkWithoutScope = true,
            sharedBulkNonNullFactPath = "resource.code"
    )
    static class SampleSharedCatalogResource {
    }

    @Test
    void allAnnotationsCarryRuntimeRetentionAndZeroFrameworkDependencies() {
        List<Class<? extends Annotation>> annotationTypes = List.of(
                AuthzTenantScope.class,
                AuthzScopeAnchor.class,
                AuthzScopeAnchors.class,
                AuthzCustodyPartition.class,
                AuthzMask.class,
                AuthzMasks.class,
                AuthzActionRule.class,
                AuthzActionRules.class
        );
        for (Class<? extends Annotation> annotationType : annotationTypes) {
            Retention retention = annotationType.getAnnotation(Retention.class);
            assertNotNull(retention, () -> annotationType.getName() + " must declare @Retention");
            assertEquals(RetentionPolicy.RUNTIME, retention.value(),
                    () -> annotationType.getName() + " must use RetentionPolicy.RUNTIME");
            assertFalse(annotationType.getName().contains("springframework"));
            assertFalse(annotationType.getName().contains("jakarta"));
        }
    }

    @Test
    void maskAndDelegationEnumsAlignWithCanonicalRegistriesAndSpecs() {
        DefaultMaskStrategyRegistry registry = new DefaultMaskStrategyRegistry();
        for (AuthzMaskStrategy strategy : AuthzMaskStrategy.values()) {
            if (strategy == AuthzMaskStrategy.CUSTOM) {
                assertEquals("", strategy.strategyId());
                continue;
            }
            MaskStrategyDescriptor descriptor = registry.findById(strategy.strategyId()).orElseThrow();
            assertEquals(descriptor.severityRank(), strategy.severityRank());
        }

        assertEquals(DualScopeDelegationSpec.ORIGIN_DESTINATION_SPLIT,
                AuthzDelegationSplitMode.ORIGIN_DESTINATION_SPLIT.modeId());
        assertTrue(AuthzDelegationSplitMode.ORIGIN_DESTINATION_SPLIT.allowsDestinationWrites());
        assertEquals(DualScopeDelegationSpec.ORIGIN_ONLY_WRITE,
                AuthzDelegationSplitMode.ORIGIN_ONLY_WRITE.modeId());
        assertFalse(AuthzDelegationSplitMode.ORIGIN_ONLY_WRITE.allowsDestinationWrites());
        assertEquals(DualScopeDelegationSpec.READ_ONLY_DESTINATION,
                AuthzDelegationSplitMode.READ_ONLY_DESTINATION.modeId());
        assertFalse(AuthzDelegationSplitMode.READ_ONLY_DESTINATION.allowsDestinationWrites());
    }

    @Test
    void declarativeAnnotationsCanBeIntrospectedOnTypesFieldsAndMethods() throws Exception {
        AuthzTenantScope tenantScope = SampleTransferResource.class.getAnnotation(AuthzTenantScope.class);
        assertNotNull(tenantScope);
        assertEquals(AuthzTenantScopeMode.ORGANIZATIONAL_UNIT, tenantScope.mode());
        assertEquals("organizationId", tenantScope.tenantField());
        assertEquals("resource.organizationId", tenantScope.resourceFactPath());
        assertEquals("subject.organizationUnitIds", tenantScope.subjectFactPath());
        assertEquals("pol-hr-transfers", tenantScope.policyId());
        assertEquals("rule-hr-transfers-org-scope", tenantScope.ruleId());

        AuthzTenantScope sharedScope = SampleSharedCatalogResource.class.getAnnotation(AuthzTenantScope.class);
        assertNotNull(sharedScope);
        assertEquals(AuthzTenantScopeMode.AUTHENTICATED_SHARED, sharedScope.mode());
        assertTrue(sharedScope.allowBulkWithoutScope());
        assertEquals("resource.code", sharedScope.sharedBulkNonNullFactPath());

        AuthzCustodyPartition typeCustody = SampleTransferResource.class.getAnnotation(AuthzCustodyPartition.class);
        assertNotNull(typeCustody);
        assertEquals(AuthzDelegationSplitMode.ORIGIN_DESTINATION_SPLIT, typeCustody.mode());
        DualScopeDelegationSpec synthesizedSpec = DualScopeDelegationSpec.ofOriginAndDestination(
                typeCustody.mode().modeId(),
                typeCustody.originFactPath(),
                typeCustody.destinationFactPath(),
                Set.of(typeCustody.originExclusiveWriteAttributes()),
                Set.of(typeCustody.destinationAllowedWriteAttributes())
        );
        assertEquals("resource.originOrgId", synthesizedSpec.originFactPath());
        assertEquals("resource.destinationOrgId", synthesizedSpec.destinationFactPath());
        assertEquals(Set.of("hr.transfers.start_date"), synthesizedSpec.originExclusiveWriteAttributes());
        assertEquals(Set.of("hr.transfers.local_notes"), synthesizedSpec.destinationAllowedWriteAttributes());

        AuthzScopeAnchor[] typeAnchors = SampleTransferResource.class.getAnnotationsByType(AuthzScopeAnchor.class);
        assertEquals(2, typeAnchors.length);
        assertEquals("hr.transfers.origin_org_id", typeAnchors[0].attributeId());

        Field originField = SampleTransferResource.class.getDeclaredField("originOrgId");
        AuthzScopeAnchor fieldAnchor = originField.getAnnotation(AuthzScopeAnchor.class);
        assertNotNull(fieldAnchor);
        assertTrue(fieldAnchor.requiredOnCreate());
        assertTrue(fieldAnchor.forbidClearOnUpdate());
        assertTrue(fieldAnchor.immutableAfterCreate());
        AuthzCustodyPartition originPartition = originField.getAnnotation(AuthzCustodyPartition.class);
        assertNotNull(originPartition);
        assertEquals(AuthzCustodyRole.ORIGIN, originPartition.role());
        assertTrue(originPartition.custodyAnchor());
        assertEquals("subject.organizationUnitIds", originPartition.subjectFactPath());

        Field medicalField = SampleTransferResource.class.getDeclaredField("medicalCode");
        AuthzMask[] masks = medicalField.getAnnotationsByType(AuthzMask.class);
        assertEquals(2, masks.length);
        assertEquals(AuthzMaskStrategy.REDACT_CONSTANT, masks[0].strategy());
        assertEquals("***CONFIDENTIAL***", masks[0].replacement());
        assertArrayEquals(new String[]{"detail"}, masks[0].surfaces());
        assertEquals(AuthzMaskStrategy.PARTIAL_MASK, masks[1].strategy());
        assertEquals(1, masks[1].visiblePrefix());
        assertEquals(1, masks[1].visibleSuffix());
        assertArrayEquals(new EvaluationMode[]{EvaluationMode.SEARCH}, masks[1].modes());

        AuthzActionRule[] typeRules = SampleTransferResource.class.getAnnotationsByType(AuthzActionRule.class);
        assertEquals(2, typeRules.length);
        assertEquals("detail", typeRules[0].surfaceKey());
        assertEquals("reconcile-batch", typeRules[1].actionKey());
        assertArrayEquals(new EvaluationMode[]{EvaluationMode.SEARCH, EvaluationMode.TARGET},
                typeRules[1].evaluationModes());

        Method approveMethod = SampleTransferResource.class.getDeclaredMethod("approve");
        AuthzActionRule approveRule = approveMethod.getAnnotation(AuthzActionRule.class);
        assertNotNull(approveRule);
        assertEquals("approve", approveRule.actionKey());
        assertArrayEquals(new String[]{"HR_APPROVER"}, approveRule.requiredRoles());
        assertEquals("resource.status", approveRule.conditionFactPath());
        assertArrayEquals(new String[]{"PENDING_APPROVAL"}, approveRule.conditionAllowedValues());
        assertArrayEquals(new String[]{"hr.transfers.status", "hr.transfers.approved_at"},
                approveRule.allowedWriteAttributes());
        assertEquals("ALLOW_TRANSFER_APPROVE", approveRule.reasonCode());
    }
}
