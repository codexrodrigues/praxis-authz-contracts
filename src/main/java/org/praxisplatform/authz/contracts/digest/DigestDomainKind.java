package org.praxisplatform.authz.contracts.digest;

/**
 * Eight frozen acyclic digest domains defined by {@code decision-platform-architecture-baseline-v1.md} §19
 * ({@code BND-DIG-001..003}).
 */
public enum DigestDomainKind {
    DEFINITION_FINGERPRINT("praxis.digest.definition-fingerprint/v1", 1),
    DEPENDENCY_MANIFEST_DIGEST("praxis.digest.dependency-manifest/v1", 2),
    COMPILE_INPUT_DIGEST("praxis.digest.compile-input/v1", 3),
    GENERATED_ARTIFACT_DIGEST("praxis.digest.generated-artifact/v1", 4),
    MATERIALIZATION_FINGERPRINT("praxis.digest.materialization-fingerprint/v1", 5),
    COMPOSITION_DIGEST("praxis.digest.composition/v1", 6),
    POLICY_SET_DIGEST("praxis.digest.policy-set/v1", 7),
    BUNDLE_ARTIFACT_DIGEST("praxis.digest.bundle-artifact/v1", 8);

    private final String domainPrefix;
    private final int topologicalStage;

    DigestDomainKind(String domainPrefix, int topologicalStage) {
        this.domainPrefix = domainPrefix;
        this.topologicalStage = topologicalStage;
    }

    /** Returns the domain-separation prefix mixed into the SHA-256 preimage. */
    public String domainPrefix() {
        return domainPrefix;
    }

    /** Returns the 1-based topological stage in the acyclic derivation DAG (1..8). */
    public int topologicalStage() {
        return topologicalStage;
    }
}
