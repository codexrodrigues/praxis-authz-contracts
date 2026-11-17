package org.praxisplatform.authz.contracts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.contracts.compatibility.CompatibilityVerificationReport;
import org.praxisplatform.authz.contracts.compatibility.DecisionPointCompatibilityEntry;
import org.praxisplatform.authz.contracts.compatibility.DefaultHostPolicyCompatibilityVerifier;
import org.praxisplatform.authz.contracts.compatibility.HostPolicyCompatibilityManifest;
import org.praxisplatform.authz.contracts.compatibility.ImpactCompletenessStatus;
import org.praxisplatform.authz.contracts.compatibility.ImpactGraphBaseline;
import org.praxisplatform.authz.contracts.compatibility.RolloutActivationStrategy;
import org.praxisplatform.authz.contracts.context.FactValueType;
import org.praxisplatform.authz.contracts.digest.CanonicalDigestCalculator;
import org.praxisplatform.authz.contracts.digest.DigestDomainKind;
import org.praxisplatform.authz.contracts.digest.OpaPolicyUnitManifest;
import org.praxisplatform.authz.contracts.digest.OpaProviderIoSchemas;
import org.praxisplatform.authz.contracts.digest.OpaRuntimeCompositionManifest;
import org.praxisplatform.authz.contracts.digest.OpaRuntimeRelease;
import org.praxisplatform.authz.contracts.digest.PolicyDigestChain;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;
import org.praxisplatform.authz.contracts.envelope.ObligationDirective;
import org.praxisplatform.authz.contracts.masking.DefaultMaskStrategyRegistry;
import org.praxisplatform.authz.contracts.masking.MaskMergeOutcome;
import org.praxisplatform.authz.contracts.masking.MaskMergeStatus;
import org.praxisplatform.authz.contracts.obligation.DefaultObligationHandlerRegistry;
import org.praxisplatform.authz.contracts.obligation.ObligationFulfillmentResult;
import org.praxisplatform.authz.contracts.obligation.ObligationMergeOutcome;
import org.praxisplatform.authz.contracts.obligation.ObligationMergeStatus;

/**
 * Conformance tests for Wave 3 contracts ({@code CC08}, {@code CC09}, {@code CC10}).
 */
class Wave3CompatibilityMaskingObligationConformanceTest {

    @Test
    void cc08_hostPolicyCompatibilityVerifierAndImpactCompletenessGate() {
        String h1 = CanonicalDigestCalculator.computeDigest(DigestDomainKind.DEFINITION_FINGERPRINT, "def");
        String h2 = CanonicalDigestCalculator.computeDigest(DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, "dep");
        String h3 = CanonicalDigestCalculator.computeDigest(DigestDomainKind.COMPILE_INPUT_DIGEST, "cin");
        String h4 = CanonicalDigestCalculator.computeDigest(DigestDomainKind.GENERATED_ARTIFACT_DIGEST, "gen");
        String h5 = CanonicalDigestCalculator.computeDigest(DigestDomainKind.MATERIALIZATION_FINGERPRINT, "mat");
        String h6 = CanonicalDigestCalculator.computeDigest(DigestDomainKind.COMPOSITION_DIGEST, "cmp");
        String h7 = CanonicalDigestCalculator.computeDigest(DigestDomainKind.POLICY_SET_DIGEST, "pset");
        String h8 = CanonicalDigestCalculator.computeDigest(DigestDomainKind.BUNDLE_ARTIFACT_DIGEST, "bnd");

        String pointKey = "resource-operation/human-resources.leave-requests/assignSubstitute";
        OpaPolicyUnitManifest unit = new OpaPolicyUnitManifest(
                "unit:pol-leave-requests:v1",
                "pol-leave-requests",
                "1.0.0",
                "praxis.authz.units.pol_leave_requests_v1",
                new PolicyDigestChain(h1, h2, h3, h4, h5),
                Set.of(pointKey)
        );
        OpaRuntimeCompositionManifest comp = new OpaRuntimeCompositionManifest(
                "cmp-1", OpaProviderIoSchemas.COMBINING_PROFILE_V1, h4, List.of(unit), h6);
        OpaRuntimeRelease release = new OpaRuntimeRelease(
                "rel-1", "rev-1", "etag-1", 1L, h7, h8, OpaProviderIoSchemas.COMPILER_PROFILE_V1, comp);

        HostPolicyCompatibilityManifest hostManifest = new HostPolicyCompatibilityManifest(
                HostPolicyCompatibilityManifest.SCHEMA_VERSION_V1,
                "workforce-service",
                "workforce-service",
                "1.0.0-SNAPSHOT",
                Instant.now(),
                OpaProviderIoSchemas.REQUIRED_PROVIDER_IO_SCHEMAS_V1,
                Set.of("OMIT", "NULLIFY", "REDACT_CONSTANT", "PARTIAL_MASK", "CPF_CNPJ_PARTIAL", "HASH_TOKEN_KEYED", "SUMMARY_ONLY"),
                Set.of("REQUIRE_MFA", "REQUIRE_JUSTIFICATION", "DURABLE_AUDIT_EVIDENCE", "WATERMARK"),
                List.of(new DecisionPointCompatibilityEntry(
                        pointKey, h2, "fc-1", h2, null, null, h2, RolloutActivationStrategy.POLICY_FIRST, true))
        );

        ImpactGraphBaseline completeImpact = new ImpactGraphBaseline(
                "imp-1",
                ImpactCompletenessStatus.COMPLETE,
                Set.of("unit:pol-leave-requests:v1"),
                Set.of(pointKey),
                Set.of("REDACT_CONSTANT"),
                Set.of("REQUIRE_JUSTIFICATION"),
                Set.of()
        );

        DefaultHostPolicyCompatibilityVerifier verifier = new DefaultHostPolicyCompatibilityVerifier();
        CompatibilityVerificationReport okReport = verifier.verify(hostManifest, release, completeImpact);
        assertTrue(okReport.compatible());

        // Counterexample 1: Missing custom mask strategy on host -> fail-closed
        ImpactGraphBaseline missingMaskImpact = new ImpactGraphBaseline(
                "imp-2",
                ImpactCompletenessStatus.COMPLETE,
                Set.of("unit:pol-leave-requests:v1"),
                Set.of(pointKey),
                Set.of("CUSTOM_REGEX_MASK"),
                Set.of(),
                Set.of()
        );
        CompatibilityVerificationReport missingMaskReport = verifier.verify(hostManifest, release, missingMaskImpact);
        assertFalse(missingMaskReport.compatible());
        assertTrue(missingMaskReport.blockingMismatches().contains("COMPAT_MISSING_MASK_STRATEGY:CUSTOM_REGEX_MASK"));

        // Counterexample 2: ImpactCompletenessStatus.PARTIAL -> fail-closed (BND-IMP-002)
        ImpactGraphBaseline partialImpact = new ImpactGraphBaseline(
                "imp-3",
                ImpactCompletenessStatus.PARTIAL,
                Set.of("unit:pol-leave-requests:v1"),
                Set.of(pointKey),
                Set.of(),
                Set.of(),
                Set.of("UNRESOLVED_SELECTOR")
        );
        assertFalse(partialImpact.isPublishableForAuthoritativeExecution());
        CompatibilityVerificationReport partialReport = verifier.verify(hostManifest, release, partialImpact);
        assertFalse(partialReport.compatible());
    }

    @Test
    void cc09_maskStrategyLatticeCommutativityAssociativityIdempotencyAndConflicts() {
        DefaultMaskStrategyRegistry registry = new DefaultMaskStrategyRegistry();
        String attr = "hr.leave_requests.medical_code";

        MaskDirective omit = new MaskDirective(attr, "OMIT", Map.of());
        MaskDirective nullify = new MaskDirective(attr, "NULLIFY", Map.of());
        MaskDirective redactA = new MaskDirective(attr, "REDACT_CONSTANT", Map.of("replacement", "***RESTRICTED***"));
        MaskDirective redactB = new MaskDirective(attr, "REDACT_CONSTANT", Map.of("replacement", "***HIDDEN***"));
        MaskDirective partial1 = new MaskDirective(attr, "PARTIAL_MASK", Map.of("visiblePrefix", 3, "visibleSuffix", 0));
        MaskDirective partial2 = new MaskDirective(attr, "PARTIAL_MASK", Map.of("visiblePrefix", 0, "visibleSuffix", 4));
        MaskDirective cpfPartial = new MaskDirective(attr, "CPF_CNPJ_PARTIAL", Map.of());

        // Idempotence: redactA u redactA == redactA
        MaskMergeOutcome idem = registry.merge(redactA, redactA);
        assertEquals(MaskMergeStatus.MERGED, idem.status());
        assertEquals(redactA, idem.effectiveDirective());

        // Commutativity: redactA u partial1 == partial1 u redactA == redactA (rank 80 > rank 50)
        MaskMergeOutcome leftRight = registry.merge(redactA, partial1);
        MaskMergeOutcome rightLeft = registry.merge(partial1, redactA);
        assertEquals(MaskMergeStatus.MERGED, leftRight.status());
        assertEquals(redactA, leftRight.effectiveDirective());
        assertEquals(leftRight.effectiveDirective(), rightLeft.effectiveDirective());

        // Associativity: (partial1 u redactA) u nullify == partial1 u (redactA u nullify) == nullify
        MaskMergeOutcome assoc1 = registry.merge(registry.merge(partial1, redactA).effectiveDirective(), nullify);
        MaskMergeOutcome assoc2 = registry.merge(partial1, registry.merge(redactA, nullify).effectiveDirective());
        assertEquals(nullify, assoc1.effectiveDirective());
        assertEquals(assoc1.effectiveDirective(), assoc2.effectiveDirective());

        // OMIT dominates NULLIFY (rank 100 > rank 90)
        assertEquals(omit, registry.merge(nullify, omit).effectiveDirective());

        // Parameter conflict on same strategy -> MASK_CONFLICT
        assertEquals(MaskMergeStatus.MASK_CONFLICT, registry.merge(redactA, redactB).status());
        assertEquals(MaskMergeStatus.MASK_CONFLICT, registry.merge(partial1, partial2).status());

        // Incomparable strategies at same rank 50 (CPF_CNPJ_PARTIAL vs PARTIAL_MASK) -> MASK_CONFLICT
        assertEquals(MaskMergeStatus.MASK_CONFLICT, registry.merge(cpfPartial, partial1).status());

        // Counterexample 1 (CC09): NULLIFY on non-nullable target field is rejected
        assertFalse(registry.isCompatibleWithTargetField(nullify, FactValueType.STRING, false));
        assertTrue(registry.isCompatibleWithTargetField(nullify, FactValueType.STRING, true));
        assertTrue(registry.isCompatibleWithTargetField(redactA, FactValueType.STRING, false));

        // P1-R06: FIELD_USE(VALUE)=DENY dominates any mask directive (PCB-MASK-001)
        MaskMergeOutcome dominated = registry.resolveForField(List.of(partial1, redactA), true);
        assertEquals(MaskMergeStatus.DOMINATED_BY_FIELD_USE_DENY, dominated.status());
        MaskMergeOutcome resolved = registry.resolveForField(List.of(partial1, redactA), false);
        assertEquals(MaskMergeStatus.MERGED, resolved.status());
        assertEquals(redactA, resolved.effectiveDirective());
    }

    @Test
    void cc10_obligationParameterMergerCommutativityAndFailClosedBarrier() {
        DefaultObligationHandlerRegistry registry = new DefaultObligationHandlerRegistry();

        ObligationDirective just15 = new ObligationDirective(
                "REQUIRE_JUSTIFICATION", "ON_PERMIT", "BEFORE_EXECUTION", Map.of("minLength", 15));
        ObligationDirective just30 = new ObligationDirective(
                "REQUIRE_JUSTIFICATION", "ON_PERMIT", "BEFORE_EXECUTION", Map.of("minLength", 30));

        // Commutative max(minLength) merge
        ObligationMergeOutcome m1 = registry.merge(just15, just30);
        ObligationMergeOutcome m2 = registry.merge(just30, just15);
        assertEquals(ObligationMergeStatus.MERGED, m1.status());
        assertEquals(30, m1.mergedDirective().parameters().get("minLength"));
        assertEquals(m1.mergedDirective(), m2.mergedDirective());

        // P1-R06: REQUIRE_MFA merges both min(maxAuthAgeSeconds) and union(requiredFactors)
        ObligationDirective mfaTotp = new ObligationDirective(
                "REQUIRE_MFA", "ON_PERMIT", "BEFORE_EXECUTION",
                Map.of("maxAuthAgeSeconds", 300, "requiredFactors", List.of("TOTP")));
        ObligationDirective mfaWebauthn = new ObligationDirective(
                "REQUIRE_MFA", "ON_PERMIT", "BEFORE_EXECUTION",
                Map.of("maxAuthAgeSeconds", 120, "requiredFactors", List.of("WEBAUTHN")));
        ObligationMergeOutcome mfaMerged = registry.merge(mfaTotp, mfaWebauthn);
        assertEquals(ObligationMergeStatus.MERGED, mfaMerged.status());
        assertEquals(120, mfaMerged.mergedDirective().parameters().get("maxAuthAgeSeconds"));
        assertEquals(List.of("TOTP", "WEBAUTHN"), mfaMerged.mergedDirective().parameters().get("requiredFactors"));

        // P1-R06: Unsupported barrier on REQUIRE_MFA -> OBLIGATION_CONFLICT
        ObligationDirective mfaWrongBarrier = new ObligationDirective(
                "REQUIRE_MFA", "ON_PERMIT", "BEFORE_DISCLOSURE", Map.of("maxAuthAgeSeconds", 120));
        assertEquals(ObligationMergeStatus.OBLIGATION_CONFLICT, registry.merge(mfaWrongBarrier, mfaWrongBarrier).status());

        // Commutative union of auditCategories for DURABLE_AUDIT_EVIDENCE
        ObligationDirective audA = new ObligationDirective(
                "DURABLE_AUDIT_EVIDENCE", "ON_PERMIT", "BEFORE_COMMIT_OUTBOX", Map.of("auditCategory", "CAT_B"));
        ObligationDirective audB = new ObligationDirective(
                "DURABLE_AUDIT_EVIDENCE", "ON_PERMIT", "BEFORE_COMMIT_OUTBOX", Map.of("auditCategory", "CAT_A"));
        ObligationMergeOutcome audMerged = registry.merge(audA, audB);
        assertEquals(ObligationMergeStatus.MERGED, audMerged.status());
        assertEquals(List.of("CAT_A", "CAT_B"), audMerged.mergedDirective().parameters().get("auditCategories"));

        // Unknown obligation type -> UNKNOWN_OBLIGATION_TYPE
        ObligationDirective unknown = new ObligationDirective(
                "SEND_EXTERNAL_WEBHOOK", "ON_PERMIT", "BEFORE_EXECUTION", Map.of());
        assertEquals(ObligationMergeStatus.UNKNOWN_OBLIGATION_TYPE, registry.merge(unknown, unknown).status());

        // ENF-OBL-003: Unfulfilled obligation at barrier blocks PERMIT disposition
        ObligationFulfillmentResult fulfilled = registry.findHandler("REQUIRE_JUSTIFICATION").orElseThrow()
                .fulfill(m1.mergedDirective(), Map.of("justificationText", "Emergency substitution approved by manager"));
        assertTrue(fulfilled.fulfilled());

        ObligationFulfillmentResult unfulfilled = registry.findHandler("DURABLE_AUDIT_EVIDENCE").orElseThrow()
                .fulfill(audMerged.mergedDirective(), Map.of("auditOutboxPersisted", false));
        assertFalse(unfulfilled.fulfilled());

        assertTrue(DefaultObligationHandlerRegistry.canHonorPermitDisposition(List.of(fulfilled)));
        assertFalse(DefaultObligationHandlerRegistry.canHonorPermitDisposition(List.of(fulfilled, unfulfilled)));
    }
}
