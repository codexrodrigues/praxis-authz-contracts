package org.praxisplatform.authz.contracts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.contracts.authority.EffectiveAuthorityBinding;
import org.praxisplatform.authz.contracts.authority.ExecutionDispositionMode;
import org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode;
import org.praxisplatform.authz.contracts.binding.EnforcementPipelineStep;
import org.praxisplatform.authz.contracts.binding.HostEnforcementPhase;
import org.praxisplatform.authz.contracts.binding.InMemoryRuntimeEnforcementBindingRegistry;
import org.praxisplatform.authz.contracts.binding.ReadinessEvidenceOverlay;
import org.praxisplatform.authz.contracts.binding.ReadinessStage;
import org.praxisplatform.authz.contracts.binding.RuntimeEnforcementBinding;
import org.praxisplatform.authz.contracts.binding.TransactionCardinality;
import org.praxisplatform.authz.contracts.binding.WriteChangeKind;
import org.praxisplatform.authz.contracts.binding.WriteFieldChange;
import org.praxisplatform.authz.contracts.binding.WriteIntent;
import org.praxisplatform.authz.contracts.context.ContextCompositionProfile;
import org.praxisplatform.authz.contracts.context.ContextEvaluationPhase;
import org.praxisplatform.authz.contracts.context.EvaluationContextSnapshot;
import org.praxisplatform.authz.contracts.context.FactCardinality;
import org.praxisplatform.authz.contracts.context.FactContract;
import org.praxisplatform.authz.contracts.context.FactDescriptor;
import org.praxisplatform.authz.contracts.context.FactFreshnessPolicy;
import org.praxisplatform.authz.contracts.context.FactPresenceModel;
import org.praxisplatform.authz.contracts.context.FactResolutionStage;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.context.FactSlotNamespace;
import org.praxisplatform.authz.contracts.context.FactUnavailableCause;
import org.praxisplatform.authz.contracts.context.FactValueType;
import org.praxisplatform.authz.contracts.context.ProviderInputProjection;
import org.praxisplatform.authz.contracts.context.ResolvedFactValue;
import org.praxisplatform.authz.contracts.context.TemporalContext;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionKind;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointIdentity;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointKind;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointProvenance;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionResultContractKind;
import org.praxisplatform.authz.contracts.decisionpoint.EnforcementCapability;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.decisionpoint.FactContractRef;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.decisionpoint.ObligationSupportProfile;
import org.praxisplatform.authz.contracts.decisionpoint.PointAuthorityMode;
import org.praxisplatform.authz.contracts.decisionpoint.SchemaDigestRef;
import org.praxisplatform.authz.contracts.digest.CanonicalDigestCalculator;
import org.praxisplatform.authz.contracts.digest.DigestDomainKind;
import org.praxisplatform.authz.contracts.digest.OpaRuntimeHead;
import org.praxisplatform.authz.contracts.envelope.ContributionAuthority;
import org.praxisplatform.authz.contracts.envelope.DecisionEvidence;
import org.praxisplatform.authz.contracts.envelope.EnforcementDisposition;
import org.praxisplatform.authz.contracts.envelope.GateOutcome;
import org.praxisplatform.authz.contracts.envelope.PolicyConflictIssue;
import org.praxisplatform.authz.contracts.envelope.PolicyUnitContributionTrace;
import org.praxisplatform.authz.contracts.envelope.ProviderEvaluationEnvelope;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;

/**
 * Conformance tests for Wave 1 contracts ({@code CC04}, {@code CC05}, {@code CC06}, {@code CC07},
 * {@code CC11}, {@code CC12}).
 */
class Wave1CoreContractsConformanceTest {

    @Test
    void cc04_factContractSixStatesAndMinimization() {
        FactDescriptor subjectId = new FactDescriptor(
                "subject.principalId",
                FactSlotNamespace.SUBJECT,
                FactValueType.STRING,
                FactCardinality.SCALAR,
                FactPresenceModel.ALWAYS_PRESENT,
                null,
                null,
                FactResolutionStage.EXTRACT,
                Set.of(ContextEvaluationPhase.ADMISSION, ContextEvaluationPhase.TARGET),
                false,
                "INTERNAL",
                "OPERATIONAL",
                Set.of(),
                "HUMAN_RESOURCES_ADMINISTRATION",
                null
        );
        FactDescriptor cidFact = new FactDescriptor(
                "resource.cidCodigo",
                FactSlotNamespace.RESOURCE,
                FactValueType.STRING,
                FactCardinality.SCALAR,
                FactPresenceModel.MAY_BE_ABSENT,
                "ergon.afastamentos.cid_codigo",
                null,
                FactResolutionStage.EXTRACT,
                Set.of(ContextEvaluationPhase.TARGET),
                true,
                "RESTRICTED",
                "SENSITIVE_PERSONAL",
                Set.of("HEALTH_DATA"),
                "OFFICIAL_HEALTH_EXPERTISE",
                new FactFreshnessPolicy(300)
        );

        // R-02: Imaginary classification HEALTH_BIOMETRIC must be rejected
        assertThrows(IllegalArgumentException.class, () -> new FactDescriptor(
                "resource.cidCodigo",
                FactSlotNamespace.RESOURCE,
                FactValueType.STRING,
                FactCardinality.SCALAR,
                FactPresenceModel.MAY_BE_ABSENT,
                "ergon.afastamentos.cid_codigo",
                null,
                FactResolutionStage.EXTRACT,
                Set.of(ContextEvaluationPhase.TARGET),
                true,
                "HEALTH_BIOMETRIC",
                "SENSITIVE_PERSONAL",
                Set.of("HEALTH_DATA"),
                "OFFICIAL_HEALTH_EXPERTISE",
                null
        ));

        String fcDigest = CanonicalDigestCalculator.computeDigest(
                DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, "fc-afastamentos-v1");
        FactContract contract = new FactContract(
                FactContract.SCHEMA_VERSION_V1,
                "human-resources.afastamentos:default-authz-facts",
                "1.0.0",
                fcDigest,
                "human-resources.afastamentos",
                Map.of(
                        subjectId.factPath(), subjectId,
                        cidFact.factPath(), cidFact
                )
        );

        ContextCompositionProfile profile = new ContextCompositionProfile(
                ContextCompositionProfile.SCHEMA_VERSION_V1,
                "prof-afastamentos-target",
                "resource-operation/human-resources.afastamentos/findById",
                ContextEvaluationPhase.TARGET,
                contract.factContractId(),
                contract.factContractDigest(),
                Set.of("subject.principalId"),
                Set.of("resource.cidCodigo"),
                250L,
                true
        );

        // R-08: Verify all 6 frozen FactResolutionStatus states
        assertEquals(6, FactResolutionStatus.values().length);
        assertEquals(FactResolutionStatus.PRESENT, ResolvedFactValue.present("subject.principalId", "usr-1").status());
        assertEquals(FactResolutionStatus.NULL, ResolvedFactValue.explicitNull("resource.cidCodigo").status());
        assertEquals(FactResolutionStatus.ABSENT, ResolvedFactValue.absent("resource.cidCodigo").status());
        assertEquals(FactResolutionStatus.STALE, ResolvedFactValue.stale("subject.principalId", "STALE_CACHE").status());
        assertEquals(FactResolutionStatus.UNAVAILABLE,
                ResolvedFactValue.unavailable("subject.principalId", FactUnavailableCause.SOURCE_TIMEOUT, "TIMEOUT").status());
        assertEquals(FactResolutionStatus.ERROR, ResolvedFactValue.error("subject.principalId", "ERR").status());

        EvaluationContextSnapshot snapshot = new EvaluationContextSnapshot(
                EvaluationContextSnapshot.SCHEMA_VERSION_V1,
                "snap-1",
                profile.profileId(),
                contract.factContractId(),
                contract.factContractDigest(),
                ContextEvaluationPhase.TARGET,
                new TemporalContext(Instant.parse("2026-11-08T17:00:00Z"), ZoneId.of("America/Sao_Paulo")),
                Map.of(
                        "subject.principalId", ResolvedFactValue.present("subject.principalId", "usr-9910"),
                        "resource.cidCodigo", ResolvedFactValue.present("resource.cidCodigo", "J11")
                ),
                Set.of()
        );

        // Minimization omits unreferenced RESTRICTED/SENSITIVE_PERSONAL fact
        ProviderInputProjection projection = ProviderInputProjection.fromSnapshot(
                "TARGET",
                snapshot,
                contract,
                profile,
                Set.of("subject.principalId")
        );
        assertTrue(projection.omittedSensitiveFactPaths().contains("resource.cidCodigo"));
        assertFalse(projection.projectedInput().containsKey("resource.cidCodigo"));
        assertEquals("usr-9910", projection.projectedInput().get("subject.principalId"));

        // P1-R03: Reject overlapping required and optional fact paths in ContextCompositionProfile
        assertThrows(IllegalArgumentException.class, () -> new ContextCompositionProfile(
                ContextCompositionProfile.SCHEMA_VERSION_V1,
                "prof-overlap",
                "resource-operation/human-resources.afastamentos/findById",
                ContextEvaluationPhase.TARGET,
                contract.factContractId(),
                contract.factContractDigest(),
                Set.of("subject.principalId"),
                Set.of("subject.principalId"),
                250L,
                true
        ));

        // P1-R03: Reject non-NONE unavailableCause on non-UNAVAILABLE status
        assertThrows(IllegalArgumentException.class, () -> new ResolvedFactValue(
                "subject.principalId",
                FactResolutionStatus.NULL,
                null,
                FactUnavailableCause.SOURCE_TIMEOUT,
                null
        ));

        // P1-R03: Reject TARGET-only fact in SEARCH mode projection
        assertThrows(IllegalArgumentException.class, () -> ProviderInputProjection.fromSnapshot(
                "SEARCH",
                snapshot,
                contract,
                profile,
                Set.of("subject.principalId", "resource.cidCodigo")
        ));
    }

    @Test
    void cc05_decisionPointIdentityGrammarAndFieldUseVocabulary() {
        // R-01: EXPORT, LOOKUP, and GROUP_BY must be rejected as FieldUseCategory tokens
        assertEquals(FieldUseCategory.GROUP, FieldUseCategory.fromWireName("GROUP"));
        assertEquals(FieldUseCategory.JOIN, FieldUseCategory.fromWireName("JOIN"));
        assertThrows(IllegalArgumentException.class, () -> FieldUseCategory.fromWireName("EXPORT"));
        assertThrows(IllegalArgumentException.class, () -> FieldUseCategory.fromWireName("LOOKUP"));
        assertThrows(IllegalArgumentException.class, () -> FieldUseCategory.fromWireName("GROUP_BY"));

        // R-06: Canonical DecisionPointIdentity grammar
        DecisionPointIdentity identity = DecisionPointIdentity.resourceOperation(
                "praxis-ergon-showcase",
                "human-resources.afastamentos",
                "atualizarSubstituto"
        );
        assertEquals("resource-operation/human-resources.afastamentos/atualizarSubstituto", identity.pointKey());

        // Legacy colon-delimited key must be rejected
        assertThrows(IllegalArgumentException.class, () -> new DecisionPointIdentity(
                "resource:human-resources.afastamentos:operation:atualizarSubstituto",
                DecisionPointKind.RESOURCE_OPERATION,
                "praxis-ergon-showcase",
                "human-resources.afastamentos",
                "atualizarSubstituto"
        ));

        String dpDigest = CanonicalDigestCalculator.computeDigest(
                DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, identity.pointKey());
        DecisionPointDescriptor descriptor = new DecisionPointDescriptor(
                DecisionPointDescriptor.SCHEMA_VERSION_V1,
                identity,
                DecisionKind.AUTHORIZATION,
                DecisionResultContractKind.GATE,
                "atualizar-substituto",
                "UPDATE_PARTIAL",
                "PATCH",
                "/api/human-resources/afastamentos/{id}/substituto",
                Set.of(EvaluationMode.TARGET),
                Set.of(EnforcementCapability.ACCESS, EnforcementCapability.FIELD_WRITE, EnforcementCapability.FIELD_USE, EnforcementCapability.MASK),
                Set.of(FieldUseCategory.VALUE),
                new ObligationSupportProfile(Set.of("REQUIRE_JUSTIFICATION"), Set.of("BEFORE_EXECUTION")),
                new FactContractRef("fc-1", dpDigest),
                null,
                new SchemaDigestRef("AfastamentoSubstitutoPatchDTO", dpDigest),
                new SchemaDigestRef("AfastamentoResponseDTO", dpDigest),
                "HUMAN_RESOURCES_ADMINISTRATION",
                "LGPD:ART_7_III",
                new DecisionPointProvenance(Set.of("OPENAPI_OPERATION"), Set.of("x-ui.governance")),
                dpDigest
        );
        assertNotNull(descriptor.toRef());

        // Counterexample: SEARCH mode without queryProjectionRef must fail (DPC-CAP-002)
        assertThrows(IllegalArgumentException.class, () -> new DecisionPointDescriptor(
                DecisionPointDescriptor.SCHEMA_VERSION_V1,
                DecisionPointIdentity.resourceOperation("praxis-ergon-showcase", "human-resources.afastamentos", "filter"),
                DecisionKind.AUTHORIZATION,
                DecisionResultContractKind.GATE,
                null,
                "SEARCH",
                "POST",
                "/api/human-resources/afastamentos/filter",
                Set.of(EvaluationMode.SEARCH),
                Set.of(EnforcementCapability.DATA_SCOPE),
                Set.of(),
                null,
                new FactContractRef("fc-1", dpDigest),
                null,
                null,
                null,
                "HUMAN_RESOURCES_ADMINISTRATION",
                "LGPD:ART_7_III",
                null,
                dpDigest
        ));
    }

    @Test
    void cc06_runtimeEnforcementBindingAndWriteIntentAnd15Steps() {
        assertEquals(15, EnforcementPipelineStep.values().length);
        assertEquals(11, EnforcementPipelineStep.STEP_11_ENFORCE_PRE_MUTATION_ACCESS_AND_FIELD_WRITE.stepNumber());
        assertEquals(12, EnforcementPipelineStep.STEP_12_EXECUTE_SERVER_HYDRATION_AND_BUSINESS_RULES.stepNumber());

        WriteFieldChange setChange = new WriteFieldChange(
                "/substitutoMatricula",
                "ergon.afastamentos.substituto_matricula",
                WriteChangeKind.SET,
                "MAT-20499"
        );
        WriteFieldChange clearChange = new WriteFieldChange(
                "/observacao",
                "ergon.afastamentos.observacao",
                WriteChangeKind.CLEAR_EXPLICIT_NULL,
                null
        );
        WriteIntent writeIntent = new WriteIntent(
                "UPDATE_PARTIAL",
                true,
                BatchAuthorizationMode.REJECT_ALL,
                TransactionCardinality.SINGLE_ITEM,
                List.of(setChange, clearChange)
        );
        assertEquals(
                Set.of("ergon.afastamentos.substituto_matricula", "ergon.afastamentos.observacao"),
                writeIntent.modifiedAttributeIds()
        );

        DecisionPointIdentity id = DecisionPointIdentity.resourceOperation(
                "praxis-ergon-showcase", "human-resources.afastamentos", "atualizarSubstituto");
        String digest = CanonicalDigestCalculator.computeDigest(DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, "dp");
        RuntimeEnforcementBinding binding1 = new RuntimeEnforcementBinding(
                RuntimeEnforcementBinding.SCHEMA_VERSION_V1,
                "bind-1",
                new org.praxisplatform.authz.contracts.decisionpoint.DecisionPointRef(
                        id.pointKey(), id.pointKind(), id.serviceKey(), id.resourceKey(), id.operationOrActionKey(), digest),
                EvaluationMode.TARGET,
                EnforcementCapability.ACCESS,
                Set.of(),
                HostEnforcementPhase.PRE_MUTATION,
                "OPA_REGO_V1",
                PointAuthorityMode.AUTHORITATIVE,
                "praxis.enforcement-profile.spring-jpa/v1",
                "DefaultAccessHandler/v1",
                "praxis.authz-host-contract/v1",
                BatchAuthorizationMode.REJECT_ALL,
                TransactionCardinality.SINGLE_ITEM,
                digest,
                new ReadinessEvidenceOverlay(
                        Set.of(
                                ReadinessStage.STRUCTURAL_READY,
                                ReadinessStage.POLICY_READY,
                                ReadinessStage.PROVIDER_READY,
                                ReadinessStage.ENFORCEMENT_READY),
                        "rev-1",
                        digest,
                        Instant.now()
                )
        );
        assertTrue(binding1.isAuthoritativeReady());

        // BND-SEM-005: Duplicate binding for the same (pointKey, mode, capability) must fail
        RuntimeEnforcementBinding duplicate = new RuntimeEnforcementBinding(
                RuntimeEnforcementBinding.SCHEMA_VERSION_V1,
                "bind-2",
                binding1.decisionPointRef(),
                EvaluationMode.TARGET,
                EnforcementCapability.ACCESS,
                Set.of(),
                HostEnforcementPhase.PRE_MUTATION,
                "OTHER_PROVIDER_V1",
                PointAuthorityMode.AUTHORITATIVE,
                "praxis.enforcement-profile.spring-jpa/v1",
                "DefaultAccessHandler/v1",
                "praxis.authz-host-contract/v1",
                BatchAuthorizationMode.REJECT_ALL,
                TransactionCardinality.SINGLE_ITEM,
                digest,
                null
        );
        assertThrows(IllegalArgumentException.class,
                () -> new InMemoryRuntimeEnforcementBindingRegistry(List.of(binding1, duplicate)));
    }

    @Test
    void cc07_cc11_cc12_envelopeUndefinedFailClosedAndAuthorityConvergenceAndDigests() {
        // OPA-RT-004: HTTP 200 {} without 'result' must produce GateOutcome.TECHNICAL_ERROR
        ProviderEvaluationEnvelope undefinedEnv = ProviderEvaluationEnvelope.failClosedForUndefinedOpaResult(
                Map.of(),
                "resource-operation/human-resources.afastamentos/findById",
                EvaluationMode.TARGET,
                "sha256:8f9d2a1b4c6e7f01928374655647382910abcdef1234567890abcdef12345678",
                Instant.now()
        );
        assertEquals(GateOutcome.TECHNICAL_ERROR, undefinedEnv.gateOutcome());
        assertEquals(
                ProviderEvaluationEnvelope.OPA_UNDEFINED_DECISION_DOCUMENT,
                undefinedEnv.evaluationIssues().get(0).issueCode()
        );

        EffectiveAuthorityBinding authBinding = new EffectiveAuthorityBinding(
                "AUTHORITATIVE",
                ExecutionDispositionMode.AUTHORITATIVE_EXECUTION,
                PointAuthorityMode.AUTHORITATIVE
        );
        assertEquals(EnforcementDisposition.DENY, authBinding.normalizeDisposition(true, true, undefinedEnv));

        // ENF-GEN-019: GateOutcome.ALLOW with unresolvedConflicts must normalize to DENY
        ProviderEvaluationEnvelope conflictedEnv = new ProviderEvaluationEnvelope(
                ProviderEvaluationEnvelope.SCHEMA_VERSION_V1,
                "OPA_REGO_V1",
                "eval-conflict",
                "resource-operation/human-resources.afastamentos/findById",
                EvaluationMode.TARGET,
                "praxis.authorization-combining/v1",
                "rev-1",
                "sha256:99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa",
                "sha256:8f9d2a1b4c6e7f01928374655647382910abcdef1234567890abcdef12345678",
                GateOutcome.ALLOW,
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(new PolicyConflictIssue(
                        "MASK_CONFLICT",
                        "ergon.afastamentos.cid_codigo",
                        Set.of("unit:p1:v1", "unit:p2:v1"),
                        "Conflicting mask parameters")),
                List.of(new PolicyUnitContributionTrace(
                        "unit:p1:v1", "p1", "r1", ContributionAuthority.GRANT, RuleEffect.ALLOW, "ALLOW_READ")),
                List.of(),
                Instant.now(),
                500L
        );
        assertEquals(EnforcementDisposition.DENY, authBinding.normalizeDisposition(true, true, conflictedEnv));

        // RESTRICT_BASELINE never expands access when structuralBaselineAllowed == false (PCB-AUTH-003)
        EffectiveAuthorityBinding restrictBinding = new EffectiveAuthorityBinding(
                "CAN_BLOCK_PROVEN_DENY",
                ExecutionDispositionMode.AUTHORITATIVE_EXECUTION,
                PointAuthorityMode.RESTRICT_BASELINE
        );
        ProviderEvaluationEnvelope cleanAllowEnv = new ProviderEvaluationEnvelope(
                ProviderEvaluationEnvelope.SCHEMA_VERSION_V1,
                "OPA_REGO_V1",
                "eval-ok",
                "resource-operation/human-resources.afastamentos/findById",
                EvaluationMode.TARGET,
                "praxis.authorization-combining/v1",
                "rev-1",
                "sha256:99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa",
                "sha256:8f9d2a1b4c6e7f01928374655647382910abcdef1234567890abcdef12345678",
                GateOutcome.ALLOW,
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(new PolicyUnitContributionTrace(
                        "unit:p1:v1", "p1", "r1", ContributionAuthority.GRANT, RuleEffect.ALLOW, "ALLOW_READ")),
                List.of(),
                Instant.now(),
                500L
        );
        assertEquals(EnforcementDisposition.DENY, restrictBinding.normalizeDisposition(true, false, cleanAllowEnv));
        assertEquals(EnforcementDisposition.PERMIT, authBinding.normalizeDisposition(true, false, cleanAllowEnv));

        // P1-R01: SHADOW mode never expands access beyond structuralBaselineAllowed
        EffectiveAuthorityBinding shadowAuthBinding = new EffectiveAuthorityBinding(
                "AUTHORITATIVE",
                ExecutionDispositionMode.SHADOW,
                PointAuthorityMode.AUTHORITATIVE
        );
        assertFalse(shadowAuthBinding.canGrantAccessBeyondBaseline());
        assertEquals(EnforcementDisposition.DENY, shadowAuthBinding.normalizeDisposition(true, false, cleanAllowEnv));

        // P1-R01: TEST mode cannot execute runtime enforcement (PCB-AUTH-002)
        EffectiveAuthorityBinding testBinding = new EffectiveAuthorityBinding(
                "REFERENCE_ONLY",
                ExecutionDispositionMode.TEST,
                PointAuthorityMode.RESTRICT_BASELINE
        );
        assertThrows(IllegalStateException.class, () -> testBinding.normalizeDisposition(true, true, cleanAllowEnv));

        // P1-R05: OPA-SEARCH-004 rejects bundleArtifactDigest rotation even if runtimeRevision matches
        String otherBundleHash = CanonicalDigestCalculator.computeDigest(DigestDomainKind.BUNDLE_ARTIFACT_DIGEST, "bnd-2");
        String dummyHashForSearch = CanonicalDigestCalculator.computeDigest(DigestDomainKind.POLICY_SET_DIGEST, "ps-1");
        OpaRuntimeHead headA = new OpaRuntimeHead(
                "opa-pod-1", "rev-1", "etag-1", 1L, dummyHashForSearch, dummyHashForSearch, "v1", dummyHashForSearch);
        OpaRuntimeHead headBundleChanged = new OpaRuntimeHead(
                "opa-pod-1", "rev-1", "etag-1", 1L, dummyHashForSearch, otherBundleHash, "v1", dummyHashForSearch);
        assertFalse(OpaRuntimeHead.verifySameInstanceSearchGuard(headA, headBundleChanged));

        // P1-R05: DecisionEvidence rejects overlapping fulfilled and unfulfilled obligation types
        assertThrows(IllegalArgumentException.class, () -> new DecisionEvidence(
                "ev-2",
                "resource-operation/human-resources.afastamentos/findById",
                EvaluationMode.TARGET,
                "rev-1",
                "sha256:99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa",
                "sha256:8f9d2a1b4c6e7f01928374655647382910abcdef1234567890abcdef12345678",
                GateOutcome.DENY,
                EnforcementDisposition.DENY,
                Set.of("DENY_OBLIGATION"),
                Map.of(),
                Set.of("DURABLE_AUDIT_EVIDENCE"),
                Set.of("DURABLE_AUDIT_EVIDENCE"),
                Instant.now()
        ));

        // ENF-OBL-003: DecisionEvidence cannot record PERMIT with unfulfilled obligations
        assertThrows(IllegalArgumentException.class, () -> new DecisionEvidence(
                "ev-1",
                "resource-operation/human-resources.afastamentos/findById",
                EvaluationMode.TARGET,
                "rev-1",
                "sha256:99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa",
                "sha256:8f9d2a1b4c6e7f01928374655647382910abcdef1234567890abcdef12345678",
                GateOutcome.ALLOW,
                EnforcementDisposition.PERMIT,
                Set.of("ALLOW_READ"),
                Map.of(),
                Set.of(),
                Set.of("DURABLE_AUDIT_EVIDENCE"),
                Instant.now()
        ));

        // BND-DIG-002: Acyclic digest derivation rejects inverted stage dependency
        assertThrows(IllegalArgumentException.class, () -> CanonicalDigestCalculator.computeAcyclicDerivedDigest(
                DigestDomainKind.DEFINITION_FINGERPRINT,
                List.of(DigestDomainKind.BUNDLE_ARTIFACT_DIGEST),
                "invalid-cycle"
        ));

        // OPA-SEARCH-004: Same-instance search guard
        String dummyHash = CanonicalDigestCalculator.computeDigest(DigestDomainKind.POLICY_SET_DIGEST, "ps-1");
        OpaRuntimeHead headPre = new OpaRuntimeHead(
                "opa-pod-1", "rev-1", "etag-1", 1L, dummyHash, dummyHash, "v1", dummyHash);
        OpaRuntimeHead headPostSame = new OpaRuntimeHead(
                "opa-pod-1", "rev-1", "etag-1", 1L, dummyHash, dummyHash, "v1", dummyHash);
        OpaRuntimeHead headPostRotated = new OpaRuntimeHead(
                "opa-pod-1", "rev-2", "etag-2", 2L, dummyHash, dummyHash, "v1", dummyHash);
        assertTrue(OpaRuntimeHead.verifySameInstanceSearchGuard(headPre, headPostSame));
        assertFalse(OpaRuntimeHead.verifySameInstanceSearchGuard(headPre, headPostRotated));
    }
}
