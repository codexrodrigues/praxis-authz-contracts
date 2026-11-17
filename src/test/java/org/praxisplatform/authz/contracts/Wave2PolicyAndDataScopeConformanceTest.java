package org.praxisplatform.authz.contracts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.contracts.context.ContextEvaluationPhase;
import org.praxisplatform.authz.contracts.context.FactCardinality;
import org.praxisplatform.authz.contracts.context.FactContract;
import org.praxisplatform.authz.contracts.context.FactDescriptor;
import org.praxisplatform.authz.contracts.context.FactPresenceModel;
import org.praxisplatform.authz.contracts.context.FactResolutionStage;
import org.praxisplatform.authz.contracts.context.FactSlotNamespace;
import org.praxisplatform.authz.contracts.context.FactValueType;
import org.praxisplatform.authz.contracts.context.ResolvedFactValue;
import org.praxisplatform.authz.contracts.datascope.ComparisonPredicateIr;
import org.praxisplatform.authz.contracts.datascope.DataScopeOutcome;
import org.praxisplatform.authz.contracts.datascope.DataScopePlan;
import org.praxisplatform.authz.contracts.datascope.FieldRefOperandIr;
import org.praxisplatform.authz.contracts.datascope.KleeneSearchPredicateEvaluator;
import org.praxisplatform.authz.contracts.datascope.KleeneTruthValue;
import org.praxisplatform.authz.contracts.datascope.LiteralListOperandIr;
import org.praxisplatform.authz.contracts.datascope.LiteralOperandIr;
import org.praxisplatform.authz.contracts.datascope.LogicalPredicateIr;
import org.praxisplatform.authz.contracts.datascope.NullabilityPredicateIr;
import org.praxisplatform.authz.contracts.datascope.PushdownMode;
import org.praxisplatform.authz.contracts.datascope.QueryableFieldDescriptor;
import org.praxisplatform.authz.contracts.datascope.QueryableResourceProjection;
import org.praxisplatform.authz.contracts.datascope.SearchPredicateOperator;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionKind;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointIdentity;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionResultContractKind;
import org.praxisplatform.authz.contracts.decisionpoint.EnforcementCapability;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.decisionpoint.FactContractRef;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.decisionpoint.QueryableProjectionRef;
import org.praxisplatform.authz.contracts.digest.CanonicalDigestCalculator;
import org.praxisplatform.authz.contracts.digest.DigestDomainKind;
import org.praxisplatform.authz.contracts.digest.OpaProviderIoSchemas;
import org.praxisplatform.authz.contracts.envelope.ContributionAuthority;
import org.praxisplatform.authz.contracts.envelope.ObligationDirective;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;
import org.praxisplatform.authz.contracts.policy.AccessContributionSpec;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyDefinition;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyRule;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyValidationResult;
import org.praxisplatform.authz.contracts.policy.AuthorizationRuleContributions;
import org.praxisplatform.authz.contracts.policy.AuthorizationSourceCondition;
import org.praxisplatform.authz.contracts.policy.ConditionProfileKind;
import org.praxisplatform.authz.contracts.policy.DataScopeContributionSpec;
import org.praxisplatform.authz.contracts.policy.DefaultAuthorizationPolicyCandidateValidator;
import org.praxisplatform.authz.contracts.policy.DualScopeDelegationSpec;
import org.praxisplatform.authz.contracts.policy.FieldUseContributionSpec;
import org.praxisplatform.authz.contracts.policy.MaskContributionSpec;
import org.praxisplatform.authz.contracts.policy.PolicyFactRequirement;
import org.praxisplatform.authz.contracts.policy.PolicyFieldSelector;
import org.praxisplatform.authz.contracts.policy.PolicyMaterializationTargetSpec;
import org.praxisplatform.authz.contracts.policy.PolicyTargetSpec;

/**
 * Conformance tests for Wave 2 contracts ({@code CC01}, {@code CC02}, {@code CC03}).
 */
class Wave2PolicyAndDataScopeConformanceTest {

    @Test
    void cc01_cc02_policyDefinitionResolutionManifestsAndValidatorGates() {
        String fcDigest = CanonicalDigestCalculator.computeDigest(DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, "fc");
        String qpDigest = CanonicalDigestCalculator.computeDigest(DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, "qp");
        String dpDigest = CanonicalDigestCalculator.computeDigest(DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, "dp");

        FactDescriptor subPrincipal = new FactDescriptor(
                "subject.principalId", FactSlotNamespace.SUBJECT, FactValueType.STRING, FactCardinality.SCALAR,
                FactPresenceModel.ALWAYS_PRESENT, null, null, FactResolutionStage.EXTRACT,
                Set.of(ContextEvaluationPhase.ADMISSION, ContextEvaluationPhase.TARGET), false,
                "INTERNAL", "OPERATIONAL", Set.of(), "HUMAN_RESOURCES_ADMINISTRATION", null);
        FactDescriptor subOrgs = new FactDescriptor(
                "subject.organizationUnitIds", FactSlotNamespace.SUBJECT, FactValueType.INT64, FactCardinality.SET,
                FactPresenceModel.ALWAYS_PRESENT, null, null, FactResolutionStage.ENRICH,
                Set.of(ContextEvaluationPhase.ADMISSION, ContextEvaluationPhase.TARGET), false,
                "INTERNAL", "OPERATIONAL", Set.of(), "HUMAN_RESOURCES_ADMINISTRATION", null);
        FactDescriptor resDept = new FactDescriptor(
                "resource.departmentId", FactSlotNamespace.RESOURCE, FactValueType.INT64, FactCardinality.SCALAR,
                FactPresenceModel.ALWAYS_PRESENT, "hr.leave_requests.department_id", null, FactResolutionStage.EXTRACT,
                Set.of(ContextEvaluationPhase.TARGET), true,
                "INTERNAL", "OPERATIONAL", Set.of(), "HUMAN_RESOURCES_ADMINISTRATION", null);
        FactDescriptor resMedical = new FactDescriptor(
                "resource.medicalCode", FactSlotNamespace.RESOURCE, FactValueType.STRING, FactCardinality.SCALAR,
                FactPresenceModel.MAY_BE_ABSENT, "hr.leave_requests.medical_code", null, FactResolutionStage.EXTRACT,
                Set.of(ContextEvaluationPhase.TARGET), true,
                "RESTRICTED", "SENSITIVE_PERSONAL", Set.of("HEALTH_DATA"), "OFFICIAL_HEALTH_EXPERTISE", null);
        FactDescriptor resActive = new FactDescriptor(
                "resource.facts.isActive", FactSlotNamespace.RESOURCE, FactValueType.BOOLEAN, FactCardinality.SCALAR,
                FactPresenceModel.ALWAYS_PRESENT, null, "leaveRequest.isActive", FactResolutionStage.DERIVE,
                Set.of(ContextEvaluationPhase.TARGET), false,
                "INTERNAL", "OPERATIONAL", Set.of(), "HUMAN_RESOURCES_ADMINISTRATION", null);

        FactContract factContract = new FactContract(
                FactContract.SCHEMA_VERSION_V1,
                "fc-leave-requests",
                "1.0.0",
                fcDigest,
                "human-resources.leave-requests",
                Map.of(
                        subPrincipal.factPath(), subPrincipal,
                        subOrgs.factPath(), subOrgs,
                        resDept.factPath(), resDept,
                        resMedical.factPath(), resMedical,
                        resActive.factPath(), resActive
                )
        );

        QueryableResourceProjection queryProjection = new QueryableResourceProjection(
                QueryableResourceProjection.SCHEMA_VERSION_V1,
                "qp-leave-requests",
                "human-resources.leave-requests",
                qpDigest,
                Map.of(
                        "resource.departmentId",
                        new QueryableFieldDescriptor(
                                "resource.departmentId",
                                "hr.leave_requests.department_id",
                                FactValueType.INT64,
                                Set.of(SearchPredicateOperator.EQ, SearchPredicateOperator.IN),
                                true)
                )
        );

        DecisionPointIdentity dpId = DecisionPointIdentity.resourceOperation(
                "workforce-service", "human-resources.leave-requests", "filter");
        DecisionPointDescriptor dpFilter = new DecisionPointDescriptor(
                DecisionPointDescriptor.SCHEMA_VERSION_V1,
                dpId,
                DecisionKind.AUTHORIZATION,
                DecisionResultContractKind.GATE,
                null,
                "SEARCH",
                "POST",
                "/api/human-resources/leave-requests/filter",
                Set.of(EvaluationMode.SEARCH, EvaluationMode.TARGET),
                Set.of(EnforcementCapability.ACCESS, EnforcementCapability.DATA_SCOPE, EnforcementCapability.FIELD_USE, EnforcementCapability.MASK),
                Set.of(FieldUseCategory.VALUE, FieldUseCategory.FILTER, FieldUseCategory.SORT, FieldUseCategory.GROUP, FieldUseCategory.AGGREGATE, FieldUseCategory.JOIN),
                null,
                new FactContractRef(factContract.factContractId(), fcDigest),
                new QueryableProjectionRef(queryProjection.projectionId(), qpDigest),
                null,
                null,
                "HUMAN_RESOURCES_ADMINISTRATION",
                "LGPD:ART_7_III",
                null,
                dpDigest
        );

        AuthorizationPolicyRule validRule = new AuthorizationPolicyRule(
                "rule-department-read",
                "Allows department-scoped reads with medical code masking",
                Set.of(EvaluationMode.TARGET, EvaluationMode.SEARCH),
                new AuthorizationSourceCondition(
                        AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                        ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                        Map.of("!=", java.util.Arrays.asList(Map.of("var", "subject.principalId"), null))
                ),
                new AuthorizationRuleContributions(
                        new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                        new DataScopeContributionSpec(
                                ContributionAuthority.GRANT,
                                new AuthorizationSourceCondition(
                                        AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                                        ConditionProfileKind.AUTHORIZATION_SEARCH_SOURCE_V1,
                                        Map.of("in", List.of(
                                                Map.of("var", "resource.departmentId"),
                                                Map.of("var", "subject.organizationUnitIds")))
                                )
                        ),
                        List.of(new FieldUseContributionSpec(
                                PolicyFieldSelector.governance(
                                        Set.of("RESTRICTED"), Set.of("SENSITIVE_PERSONAL"), Set.of("HEALTH_DATA")),
                                Set.of(FieldUseCategory.FILTER, FieldUseCategory.SORT, FieldUseCategory.GROUP, FieldUseCategory.AGGREGATE, FieldUseCategory.JOIN),
                                RuleEffect.DENY
                        )),
                        List.of(),
                        List.of(new MaskContributionSpec(
                                PolicyFieldSelector.exact(Set.of("hr.leave_requests.medical_code")),
                                "REDACT_CONSTANT",
                                Map.of("replacement", "***RESTRICTED-CODE***")
                        )),
                        "AUTHZ_ALLOW_DEPARTMENT_READ"
                ),
                List.of(new ObligationDirective(
                        "DURABLE_AUDIT_EVIDENCE",
                        "ON_PERMIT",
                        "BEFORE_COMMIT_OUTBOX",
                        Map.of("auditCategory", "LEAVE_REQUEST_READ")))
        );

        AuthorizationPolicyDefinition validPolicy = new AuthorizationPolicyDefinition(
                AuthorizationPolicyDefinition.SCHEMA_VERSION_V1,
                "pol-hr-leave-requests",
                "1.0.0",
                "Leave Request Policy",
                "Governs organizational scope and health code masking",
                Set.of("ORGANIZATIONAL_SCOPE", "SENSITIVE_DATA_PROTECTION"),
                "HUMAN_RESOURCES_ADMINISTRATION",
                "LGPD:ART_7_III",
                OpaProviderIoSchemas.COMBINING_PROFILE_V1,
                List.of(PolicyTargetSpec.exact("tgt-filter", dpId.pointKey(), dpDigest, Set.of(EvaluationMode.SEARCH))),
                DualScopeDelegationSpec.ofOriginAndDestination(
                        DualScopeDelegationSpec.ORIGIN_DESTINATION_SPLIT,
                        "resource.departmentId",
                        "resource.destinationOrgId",
                        Set.of("hr.leave_requests.start_date"),
                        Set.of("hr.leave_requests.substitute_code")
                ),
                List.of(new PolicyFactRequirement("subject.organizationUnitIds", Set.of(EvaluationMode.SEARCH))),
                List.of(validRule),
                List.of(new PolicyMaterializationTargetSpec(
                        "policy_engine",
                        "opa-policy",
                        "unit:pol-hr-leave-requests:v1",
                        OpaProviderIoSchemas.COMPILER_PROFILE_V1))
        );

        DefaultAuthorizationPolicyCandidateValidator validator = new DefaultAuthorizationPolicyCandidateValidator();
        AuthorizationPolicyValidationResult validResult = validator.validate(
                validPolicy,
                Map.of(dpId.pointKey(), dpFilter),
                Map.of(factContract.factContractId(), factContract),
                Map.of(queryProjection.projectionId(), queryProjection)
        );
        assertTrue(validResult.valid());
        assertEquals(1, validResult.resolvedTargets().size());
        assertEquals(2, validResult.resolvedFieldSelectors().size());

        // Counterexample 1 (CC02): Referencing non-queryable resource.facts.isActive in authorization-search-source/v1
        List<Object> oversizedInList = new ArrayList<>();
        for (int i = 0; i < 70; i++) {
            oversizedInList.add(i);
        }
        AuthorizationPolicyRule invalidSearchRule = new AuthorizationPolicyRule(
                "rule-invalid-search",
                "Invalid SEARCH rule",
                Set.of(EvaluationMode.SEARCH),
                new AuthorizationSourceCondition(
                        AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                        ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                        Map.of("in", List.of(Map.of("var", "subject.principalId"), oversizedInList))
                ),
                new AuthorizationRuleContributions(
                        null,
                        new DataScopeContributionSpec(
                                ContributionAuthority.GRANT,
                                new AuthorizationSourceCondition(
                                        AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                                        ConditionProfileKind.AUTHORIZATION_SEARCH_SOURCE_V1,
                                        Map.of("==", List.of(Map.of("var", "resource.facts.isActive"), true))
                                )
                        ),
                        List.of(),
                        List.of(),
                        List.of(),
                        "INVALID_SEARCH"
                ),
                List.of()
        );
        AuthorizationPolicyDefinition invalidPolicy = new AuthorizationPolicyDefinition(
                AuthorizationPolicyDefinition.SCHEMA_VERSION_V1,
                "pol-invalid",
                "1.0.0",
                "Invalid Policy",
                "Rejection test",
                Set.of(),
                "HUMAN_RESOURCES_ADMINISTRATION",
                "LGPD:ART_7_III",
                OpaProviderIoSchemas.COMBINING_PROFILE_V1,
                List.of(PolicyTargetSpec.exact("tgt-filter", dpId.pointKey(), dpDigest, Set.of(EvaluationMode.SEARCH))),
                null,
                List.of(),
                List.of(invalidSearchRule),
                List.of(new PolicyMaterializationTargetSpec(
                        "policy_engine", "opa-policy", "unit:pol-invalid:v1", OpaProviderIoSchemas.COMPILER_PROFILE_V1))
        );

        AuthorizationPolicyValidationResult invalidResult = validator.validate(
                invalidPolicy,
                Map.of(dpId.pointKey(), dpFilter),
                Map.of(factContract.factContractId(), factContract),
                Map.of(queryProjection.projectionId(), queryProjection)
        );
        assertFalse(invalidResult.valid());
        assertTrue(invalidResult.diagnostics().stream()
                .anyMatch(d -> "AUTHZ_SEARCH_FACT_NOT_QUERYABLE".equals(d.code())));
        assertTrue(invalidResult.diagnostics().stream()
                .anyMatch(d -> "AUTHZ_AST_IN_LIST_LIMIT_EXCEEDED".equals(d.code())));

        // P1-R02: EXACT field selector with unknown attributeId + TARGET-only fact in SEARCH rule.when()
        AuthorizationPolicyRule invalidExactSelectorAndWhenRule = new AuthorizationPolicyRule(
                "rule-invalid-exact-and-when",
                "Rule with unknown attributeId and TARGET-only fact in SEARCH when",
                Set.of(EvaluationMode.SEARCH),
                new AuthorizationSourceCondition(
                        AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                        ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                        Map.of("==", List.of(Map.of("var", "resource.medicalCode"), "J11"))
                ),
                new AuthorizationRuleContributions(
                        new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                        null,
                        List.of(),
                        List.of(),
                        List.of(new MaskContributionSpec(
                                PolicyFieldSelector.exact(Set.of("hr.leave_requests.nonexistent_attr")),
                                "REDACT_CONSTANT",
                                Map.of("replacement", "***")
                        )),
                        "INVALID_EXACT"
                ),
                List.of()
        );
        AuthorizationPolicyDefinition invalidExactPolicy = new AuthorizationPolicyDefinition(
                AuthorizationPolicyDefinition.SCHEMA_VERSION_V1,
                "pol-invalid-exact",
                "1.0.0",
                "Invalid Selector Policy",
                "P1-R02 test",
                Set.of(),
                "HUMAN_RESOURCES_ADMINISTRATION",
                "LGPD:ART_7_III",
                OpaProviderIoSchemas.COMBINING_PROFILE_V1,
                List.of(PolicyTargetSpec.exact("tgt-filter", dpId.pointKey(), dpDigest, Set.of(EvaluationMode.SEARCH))),
                null,
                List.of(),
                List.of(invalidExactSelectorAndWhenRule),
                List.of(new PolicyMaterializationTargetSpec(
                        "policy_engine", "opa-policy", "unit:pol-invalid-exact:v1", OpaProviderIoSchemas.COMPILER_PROFILE_V1))
        );
        AuthorizationPolicyValidationResult invalidExactResult = validator.validate(
                invalidExactPolicy,
                Map.of(dpId.pointKey(), dpFilter),
                Map.of(factContract.factContractId(), factContract),
                Map.of(queryProjection.projectionId(), queryProjection)
        );
        assertFalse(invalidExactResult.valid());
        assertTrue(invalidExactResult.diagnostics().stream()
                .anyMatch(d -> "AUTHZ_FIELD_SELECTOR_UNKNOWN_ATTRIBUTE".equals(d.code())));
        assertTrue(invalidExactResult.diagnostics().stream()
                .anyMatch(d -> "AUTHZ_SEARCH_WHEN_REFERENCES_TARGET_FACT".equals(d.code())));

        // P1-R07 (from Cross-Session Review P1-R1, P1-R2, P1-R4):
        // 1. Canonical preimage determinism regardless of Set construction order
        PolicyFieldSelector selA = PolicyFieldSelector.governance(
                Set.of("RESTRICTED", "CONFIDENTIAL"),
                Set.of("SENSITIVE_PERSONAL", "PERSONAL"),
                Set.of("HEALTH_DATA", "LGPD_ART_11")
        );
        PolicyFieldSelector selB = PolicyFieldSelector.governance(
                Set.of("CONFIDENTIAL", "RESTRICTED"),
                Set.of("PERSONAL", "SENSITIVE_PERSONAL"),
                Set.of("LGPD_ART_11", "HEALTH_DATA")
        );
        assertEquals(selA.toCanonicalPreimage(), selB.toCanonicalPreimage());

        // 2. NULLIFY on ALWAYS_PRESENT (non-nullable) fact + unknown obligation type rejected by validator
        AuthorizationPolicyRule invalidMaskAndObligationRule = new AuthorizationPolicyRule(
                "rule-invalid-mask-and-ob",
                "Rule with NULLIFY on non-nullable field and unknown obligation",
                Set.of(EvaluationMode.TARGET),
                new AuthorizationSourceCondition(
                        AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                        ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                        Map.of("!=", java.util.Arrays.asList(Map.of("var", "subject.principalId"), null))
                ),
                new AuthorizationRuleContributions(
                        new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                        null,
                        List.of(),
                        List.of(),
                        List.of(new MaskContributionSpec(
                                new PolicyFieldSelector(
                                        org.praxisplatform.authz.contracts.policy.FieldSelectorKind.LINEAGE,
                                        Set.of(), Set.of(), Set.of(), Set.of(), Set.of(),
                                        "hr", "hr.leave_requests.department_", null),
                                "NULLIFY",
                                Map.of()
                        )),
                        "INVALID_MASK_AND_OB"
                ),
                List.of(new ObligationDirective(
                        "UNKNOWN_CUSTOM_OBLIGATION",
                        "ON_PERMIT",
                        "BEFORE_EXECUTION",
                        Map.of()))
        );
        AuthorizationPolicyDefinition invalidMaskAndObPolicy = new AuthorizationPolicyDefinition(
                AuthorizationPolicyDefinition.SCHEMA_VERSION_V1,
                "pol-invalid-mask-ob",
                "1.0.0",
                "Invalid Mask and Obligation Policy",
                "P1-R2 and P1-R1 LINEAGE test",
                Set.of(),
                "HUMAN_RESOURCES_ADMINISTRATION",
                "LGPD:ART_7_III",
                OpaProviderIoSchemas.COMBINING_PROFILE_V1,
                List.of(PolicyTargetSpec.exact("tgt-filter", dpId.pointKey(), dpDigest, Set.of(EvaluationMode.TARGET))),
                null,
                List.of(),
                List.of(invalidMaskAndObligationRule),
                List.of(new PolicyMaterializationTargetSpec(
                        "policy_engine", "opa-policy", "unit:pol-invalid-mask-ob:v1", OpaProviderIoSchemas.COMPILER_PROFILE_V1))
        );
        AuthorizationPolicyValidationResult invalidMaskAndObResult = validator.validate(
                invalidMaskAndObPolicy,
                Map.of(dpId.pointKey(), dpFilter),
                Map.of(factContract.factContractId(), factContract),
                Map.of(queryProjection.projectionId(), queryProjection)
        );
        assertFalse(invalidMaskAndObResult.valid());
        assertTrue(invalidMaskAndObResult.diagnostics().stream()
                .anyMatch(d -> "AUTHZ_INCOMPATIBLE_MASK_STRATEGY".equals(d.code())));
        assertTrue(invalidMaskAndObResult.diagnostics().stream()
                .anyMatch(d -> "AUTHZ_UNKNOWN_OBLIGATION_TYPE".equals(d.code())));
    }

    @Test
    @SuppressWarnings("deprecation")
    void dualScopeDelegationSupportsNeutralOriginDestinationModesAndDeprecatedAliases() {
        DualScopeDelegationSpec neutralSplit = DualScopeDelegationSpec.ofOriginAndDestination(
                "resource.originOrgId",
                "resource.destinationOrgId",
                Set.of("hr.transfers.start_date"),
                Set.of("hr.transfers.local_notes")
        );
        assertEquals(DualScopeDelegationSpec.ORIGIN_DESTINATION_SPLIT, neutralSplit.mode());
        assertEquals("resource.originOrgId", neutralSplit.originFactPath());
        assertEquals("resource.destinationOrgId", neutralSplit.destinationFactPath());
        assertEquals(Set.of("hr.transfers.start_date"), neutralSplit.originExclusiveWriteAttributes());
        assertEquals(Set.of("hr.transfers.local_notes"), neutralSplit.destinationAllowedWriteAttributes());
        assertTrue(neutralSplit.allowsDestinationWrites());
        assertFalse(neutralSplit.forbidsDestinationOnlyWrites());

        // Backward-compatible deprecated delegates return identical values
        assertEquals("resource.originOrgId", neutralSplit.cedenteFactPath());
        assertEquals("resource.destinationOrgId", neutralSplit.cessionarioFactPath());
        assertEquals(Set.of("hr.transfers.start_date"), neutralSplit.cedenteExclusiveWriteAttributes());
        assertEquals(Set.of("hr.transfers.local_notes"), neutralSplit.cessionarioAllowedWriteAttributes());

        DualScopeDelegationSpec originOnly = DualScopeDelegationSpec.ofOriginAndDestination(
                DualScopeDelegationSpec.ORIGIN_ONLY_WRITE,
                "resource.originOrgId",
                "resource.destinationOrgId",
                Set.of("hr.transfers.start_date"),
                Set.of()
        );
        assertFalse(originOnly.allowsDestinationWrites());
        assertTrue(originOnly.forbidsDestinationOnlyWrites());

        DualScopeDelegationSpec readOnlyDest = DualScopeDelegationSpec.ofOriginAndDestination(
                DualScopeDelegationSpec.READ_ONLY_DESTINATION,
                "resource.originOrgId",
                "resource.destinationOrgId",
                Set.of("hr.transfers.start_date"),
                Set.of("hr.transfers.local_notes")
        );
        assertFalse(readOnlyDest.allowsDestinationWrites());
        assertTrue(readOnlyDest.forbidsDestinationOnlyWrites());

        DualScopeDelegationSpec legacySplit = new DualScopeDelegationSpec(
                DualScopeDelegationSpec.CEDENTE_CESSIONARIO_SPLIT,
                "resource.originOrgId",
                "resource.destinationOrgId",
                Set.of("hr.transfers.a"),
                Set.of("hr.transfers.b")
        );
        assertTrue(legacySplit.allowsDestinationWrites());
        assertFalse(legacySplit.forbidsDestinationOnlyWrites());

        DualScopeDelegationSpec legacyReadOnly = new DualScopeDelegationSpec(
                DualScopeDelegationSpec.READ_ONLY_CESSIONARIO,
                "resource.originOrgId",
                "resource.destinationOrgId",
                Set.of("hr.transfers.a"),
                Set.of()
        );
        assertTrue(legacyReadOnly.forbidsDestinationOnlyWrites());

        DualScopeDelegationSpec legacyOriginOnly = new DualScopeDelegationSpec(
                DualScopeDelegationSpec.CEDENTE_ONLY_WRITE,
                "resource.originOrgId",
                "resource.destinationOrgId",
                Set.of("hr.transfers.a"),
                Set.of()
        );
        assertTrue(legacyOriginOnly.forbidsDestinationOnlyWrites());

        // Disjointness invariant remains enforced
        assertThrows(IllegalArgumentException.class, () -> DualScopeDelegationSpec.ofOriginAndDestination(
                DualScopeDelegationSpec.ORIGIN_DESTINATION_SPLIT,
                "resource.originOrgId",
                "resource.destinationOrgId",
                Set.of("hr.transfers.shared"),
                Set.of("hr.transfers.shared")
        ));
    }

    @Test
    void cc03_kleene3VlTruthTableAndPersistenceNeutralDataScopePlan() {
        ComparisonPredicateIr eq101 = new ComparisonPredicateIr(
                SearchPredicateOperator.EQ,
                "resource.departmentId",
                "hr.leave_requests.department_id",
                FactValueType.INT64,
                new LiteralOperandIr(101L),
                false
        );
        LogicalPredicateIr notEq101 = new LogicalPredicateIr(
                SearchPredicateOperator.NOT,
                List.of(eq101)
        );
        NullabilityPredicateIr isNull = new NullabilityPredicateIr(
                SearchPredicateOperator.IS_NULL,
                "resource.departmentId",
                "hr.leave_requests.department_id"
        );
        NullabilityPredicateIr isNotNull = new NullabilityPredicateIr(
                SearchPredicateOperator.IS_NOT_NULL,
                "resource.departmentId",
                "hr.leave_requests.department_id"
        );
        LogicalPredicateIr notIsNull = new LogicalPredicateIr(
                SearchPredicateOperator.NOT,
                List.of(isNull)
        );

        Map<String, ResolvedFactValue> presentMatch = Map.of(
                "resource.departmentId", ResolvedFactValue.present("resource.departmentId", 101L));
        Map<String, ResolvedFactValue> presentDiff = Map.of(
                "resource.departmentId", ResolvedFactValue.present("resource.departmentId", 202L));
        Map<String, ResolvedFactValue> explicitNull = Map.of(
                "resource.departmentId", ResolvedFactValue.explicitNull("resource.departmentId"));
        Map<String, ResolvedFactValue> structurallyMissing = Map.of(
                "resource.departmentId", ResolvedFactValue.absent("resource.departmentId"));

        // Row 1: EQ(attr, 101) -> T, F, U, U
        assertEquals(KleeneTruthValue.TRUE, KleeneSearchPredicateEvaluator.evaluate(eq101, presentMatch));
        assertEquals(KleeneTruthValue.FALSE, KleeneSearchPredicateEvaluator.evaluate(eq101, presentDiff));
        assertEquals(KleeneTruthValue.UNKNOWN, KleeneSearchPredicateEvaluator.evaluate(eq101, explicitNull));
        assertEquals(KleeneTruthValue.UNKNOWN, KleeneSearchPredicateEvaluator.evaluate(eq101, structurallyMissing));

        // Row 3: NOT(EQ(attr, 101)) -> F, T, U, U (NULL/MISSING never become TRUE under negation!)
        assertEquals(KleeneTruthValue.FALSE, KleeneSearchPredicateEvaluator.evaluate(notEq101, presentMatch));
        assertEquals(KleeneTruthValue.TRUE, KleeneSearchPredicateEvaluator.evaluate(notEq101, presentDiff));
        assertEquals(KleeneTruthValue.UNKNOWN, KleeneSearchPredicateEvaluator.evaluate(notEq101, explicitNull));
        assertEquals(KleeneTruthValue.UNKNOWN, KleeneSearchPredicateEvaluator.evaluate(notEq101, structurallyMissing));
        assertFalse(KleeneSearchPredicateEvaluator.evaluate(notEq101, explicitNull).isRowSelected());

        // Row 4 (R-03 fix): IS_NULL(attr) -> F, F, T, U
        assertEquals(KleeneTruthValue.FALSE, KleeneSearchPredicateEvaluator.evaluate(isNull, presentMatch));
        assertEquals(KleeneTruthValue.FALSE, KleeneSearchPredicateEvaluator.evaluate(isNull, presentDiff));
        assertEquals(KleeneTruthValue.TRUE, KleeneSearchPredicateEvaluator.evaluate(isNull, explicitNull));
        assertEquals(KleeneTruthValue.UNKNOWN, KleeneSearchPredicateEvaluator.evaluate(isNull, structurallyMissing));

        // Row 5 & 6 (R-03 fix): IS_NOT_NULL(attr) and NOT(IS_NULL(attr)) -> T, T, F, U
        assertEquals(KleeneTruthValue.TRUE, KleeneSearchPredicateEvaluator.evaluate(isNotNull, presentMatch));
        assertEquals(KleeneTruthValue.TRUE, KleeneSearchPredicateEvaluator.evaluate(isNotNull, presentDiff));
        assertEquals(KleeneTruthValue.FALSE, KleeneSearchPredicateEvaluator.evaluate(isNotNull, explicitNull));
        assertEquals(KleeneTruthValue.UNKNOWN, KleeneSearchPredicateEvaluator.evaluate(isNotNull, structurallyMissing));
        assertEquals(KleeneTruthValue.UNKNOWN, KleeneSearchPredicateEvaluator.evaluate(notIsNull, structurallyMissing));
        assertFalse(KleeneSearchPredicateEvaluator.evaluate(notIsNull, structurallyMissing).isRowSelected());

        // FieldRefOperandIr comparison (DSP-AST-010)
        ComparisonPredicateIr fieldRefEq = new ComparisonPredicateIr(
                SearchPredicateOperator.EQ,
                "resource.departmentId",
                "hr.leave_requests.department_id",
                FactValueType.INT64,
                new FieldRefOperandIr("resource.destinationOrgId", "hr.leave_requests.destination_org_id"),
                false
        );
        assertEquals(
                KleeneTruthValue.TRUE,
                KleeneSearchPredicateEvaluator.evaluate(
                        fieldRefEq,
                        Map.of(
                                "resource.departmentId", ResolvedFactValue.present("resource.departmentId", 505L),
                                "resource.destinationOrgId", ResolvedFactValue.present("resource.destinationOrgId", 505L)
                        ))
        );

        // Counterexample (CC03): TEXT_CONTAINS on INT64 must be rejected (DSP-IR-004)
        assertThrows(IllegalArgumentException.class, () -> new ComparisonPredicateIr(
                SearchPredicateOperator.TEXT_CONTAINS,
                "resource.departmentId",
                "hr.leave_requests.department_id",
                FactValueType.INT64,
                new LiteralOperandIr("101"),
                false
        ));

        // P1-R04: Ordered comparison on BOOLEAN and caseInsensitive on INT64 must be rejected (DSP-IR-004)
        assertThrows(IllegalArgumentException.class, () -> new ComparisonPredicateIr(
                SearchPredicateOperator.LT,
                "resource.departmentId",
                "hr.leave_requests.department_id",
                FactValueType.BOOLEAN,
                new LiteralOperandIr(true),
                false
        ));
        assertThrows(IllegalArgumentException.class, () -> new ComparisonPredicateIr(
                SearchPredicateOperator.EQ,
                "resource.departmentId",
                "hr.leave_requests.department_id",
                FactValueType.INT64,
                new LiteralOperandIr(101L),
                true
        ));

        // P1-R04: Incompatible scalar types in NE evaluate to UNKNOWN (not TRUE!)
        ComparisonPredicateIr ne101 = new ComparisonPredicateIr(
                SearchPredicateOperator.NE,
                "resource.departmentId",
                "hr.leave_requests.department_id",
                FactValueType.INT64,
                new LiteralOperandIr(101L),
                false
        );
        assertEquals(
                KleeneTruthValue.UNKNOWN,
                KleeneSearchPredicateEvaluator.evaluate(
                        ne101,
                        Map.of("resource.departmentId", ResolvedFactValue.present("resource.departmentId", "incompatible-string"))
                )
        );

        // Valid persistence-neutral DataScopePlan
        DataScopePlan plan = new DataScopePlan(
                DataScopePlan.FORMAT_V1,
                "dsp-1",
                "resource-operation/human-resources.leave-requests/filter",
                "human-resources.leave-requests",
                "rev-1",
                "sha256:99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa",
                "sha256:8f9d2a1b4c6e7f01928374655647382910abcdef1234567890abcdef12345678",
                "qp-leave-requests",
                "sha256:7766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa9988",
                DataScopeOutcome.FILTER,
                PushdownMode.FULL_PUSHDOWN,
                new ComparisonPredicateIr(
                        SearchPredicateOperator.IN,
                        "resource.departmentId",
                        "hr.leave_requests.department_id",
                        FactValueType.INT64,
                        new LiteralListOperandIr(List.of(101L, 102L)),
                        false
                )
        );
        assertEquals(DataScopeOutcome.FILTER, plan.scopeOutcome());
    }
}
