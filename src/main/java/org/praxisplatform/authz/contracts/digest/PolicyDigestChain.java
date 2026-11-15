package org.praxisplatform.authz.contracts.digest;

import java.util.Objects;

/**
 * Five-stage per-unit digest chain linking policy definition to materialization ({@code BND-DIG-001}).
 *
 * @param definitionFingerprint stage 1: semantic policy definition fingerprint
 * @param dependencyManifestDigest stage 2: target/field/fact/projection dependency manifest digest
 * @param compileInputDigest stage 3: deterministic compile input digest
 * @param generatedArtifactDigest stage 4: generated Rego/data artifact digest
 * @param materializationFingerprint stage 5: control-plane materialization record fingerprint
 */
public record PolicyDigestChain(
        String definitionFingerprint,
        String dependencyManifestDigest,
        String compileInputDigest,
        String generatedArtifactDigest,
        String materializationFingerprint
) {

    /** Validates non-blank digests across all 5 per-unit stages. */
    public PolicyDigestChain {
        definitionFingerprint = requireSha256(definitionFingerprint, "definitionFingerprint");
        dependencyManifestDigest = requireSha256(dependencyManifestDigest, "dependencyManifestDigest");
        compileInputDigest = requireSha256(compileInputDigest, "compileInputDigest");
        generatedArtifactDigest = requireSha256(generatedArtifactDigest, "generatedArtifactDigest");
        materializationFingerprint = requireSha256(materializationFingerprint, "materializationFingerprint");
    }

    private static String requireSha256(String value, String field) {
        Objects.requireNonNull(value, field + " is required");
        String trimmed = value.trim();
        if (!trimmed.startsWith("sha256:") || trimmed.length() != 71) {
            throw new IllegalArgumentException(field + " must have format 'sha256:<64-hex>': " + trimmed);
        }
        return trimmed;
    }
}
