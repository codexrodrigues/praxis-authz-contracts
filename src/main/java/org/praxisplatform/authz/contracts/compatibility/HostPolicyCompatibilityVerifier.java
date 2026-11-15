package org.praxisplatform.authz.contracts.compatibility;

import org.praxisplatform.authz.contracts.digest.OpaRuntimeRelease;

/**
 * Verifies bidirectional compatibility between a host's {@link HostPolicyCompatibilityManifest},
 * an {@link OpaRuntimeRelease}, and an {@link ImpactGraphBaseline} ({@code CC08}, {@code OPA-HANDSHAKE-001..005}).
 */
public interface HostPolicyCompatibilityVerifier {

    /**
     * Verifies compatibility and returns a fail-closed {@link CompatibilityVerificationReport}.
     *
     * @param hostManifest host compatibility manifest
     * @param runtimeRelease target OPA runtime release
     * @param impactBaseline impact graph baseline
     * @return verification report
     */
    CompatibilityVerificationReport verify(
            HostPolicyCompatibilityManifest hostManifest,
            OpaRuntimeRelease runtimeRelease,
            ImpactGraphBaseline impactBaseline
    );
}
