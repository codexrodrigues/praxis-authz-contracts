package org.praxisplatform.authz.contracts.compatibility;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.praxisplatform.authz.contracts.digest.OpaPolicyUnitManifest;
import org.praxisplatform.authz.contracts.digest.OpaProviderIoSchemas;
import org.praxisplatform.authz.contracts.digest.OpaRuntimeRelease;

/**
 * Canonical fail-closed implementation of {@link HostPolicyCompatibilityVerifier} ({@code CC08}).
 */
public final class DefaultHostPolicyCompatibilityVerifier implements HostPolicyCompatibilityVerifier {

    @Override
    public CompatibilityVerificationReport verify(
            HostPolicyCompatibilityManifest hostManifest,
            OpaRuntimeRelease runtimeRelease,
            ImpactGraphBaseline impactBaseline
    ) {
        Objects.requireNonNull(hostManifest, "hostManifest is required");
        Objects.requireNonNull(runtimeRelease, "runtimeRelease is required");
        Objects.requireNonNull(impactBaseline, "impactBaseline is required");

        List<String> mismatches = new ArrayList<>();

        if (!impactBaseline.isPublishableForAuthoritativeExecution()) {
            mismatches.add("COMPAT_IMPACT_NOT_COMPLETE:" + impactBaseline.completenessStatus());
            for (String reason : impactBaseline.blockingReasons()) {
                mismatches.add("COMPAT_IMPACT_BLOCKING_REASON:" + reason);
            }
        }

        if (!hostManifest.supportedProviderIoSchemas().containsAll(OpaProviderIoSchemas.REQUIRED_PROVIDER_IO_SCHEMAS_V1)) {
            mismatches.add("COMPAT_MISSING_PROVIDER_IO_SCHEMA");
        }

        for (String strategyId : impactBaseline.requiredMaskStrategyIds()) {
            if (!hostManifest.registeredMaskStrategyIds().contains(strategyId)) {
                mismatches.add("COMPAT_MISSING_MASK_STRATEGY:" + strategyId);
            }
        }

        for (String obligationType : impactBaseline.requiredObligationTypes()) {
            if (!hostManifest.registeredObligationTypes().contains(obligationType)) {
                mismatches.add("COMPAT_MISSING_OBLIGATION_HANDLER:" + obligationType);
            }
        }

        Map<String, DecisionPointCompatibilityEntry> hostEntriesByKey = new LinkedHashMap<>();
        for (DecisionPointCompatibilityEntry entry : hostManifest.decisionPointBindings()) {
            hostEntriesByKey.put(entry.pointKey(), entry);
        }

        for (OpaPolicyUnitManifest unit : runtimeRelease.compositionManifest().policyUnits()) {
            for (String targetPointKey : unit.targetPointKeys()) {
                verifyPointKeyBinding(targetPointKey, hostEntriesByKey, mismatches);
            }
        }
        for (String impactedPointKey : impactBaseline.impactedPointKeys()) {
            verifyPointKeyBinding(impactedPointKey, hostEntriesByKey, mismatches);
        }

        return new CompatibilityVerificationReport(
                mismatches.isEmpty(),
                runtimeRelease.runtimeRevision(),
                runtimeRelease.policySetDigest(),
                impactBaseline.completenessStatus(),
                mismatches
        );
    }

    private static void verifyPointKeyBinding(
            String pointKey,
            Map<String, DecisionPointCompatibilityEntry> hostEntriesByKey,
            List<String> mismatches
    ) {
        DecisionPointCompatibilityEntry hostEntry = hostEntriesByKey.get(pointKey);
        if (hostEntry == null) {
            String code = "COMPAT_MISSING_DECISION_POINT_BINDING:" + pointKey;
            if (!mismatches.contains(code)) {
                mismatches.add(code);
            }
        } else if (!hostEntry.enforcementReady()
                && hostEntry.activationStrategy() != RolloutActivationStrategy.HARD_DEFAULT) {
            String code = "COMPAT_DECISION_POINT_NOT_ENFORCEMENT_READY:" + pointKey;
            if (!mismatches.contains(code)) {
                mismatches.add(code);
            }
        }
    }
}
