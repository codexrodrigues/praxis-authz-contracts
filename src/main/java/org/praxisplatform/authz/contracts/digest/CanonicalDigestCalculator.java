package org.praxisplatform.authz.contracts.digest;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

/**
 * Domain-separated SHA-256 calculator enforcing the acyclic digest derivation rules
 * ({@code BND-DIG-001..003}).
 */
public final class CanonicalDigestCalculator {

    private CanonicalDigestCalculator() {}

    /**
     * Computes a canonical lowercase {@code sha256:<64-hex>} digest for the given {@link DigestDomainKind}
     * and canonical payload string.
     *
     * @param domain digest domain kind
     * @param canonicalPayload canonical preimage payload
     * @return {@code sha256:<64-hex>} digest string
     */
    public static String computeDigest(DigestDomainKind domain, String canonicalPayload) {
        Objects.requireNonNull(domain, "domain is required");
        Objects.requireNonNull(canonicalPayload, "canonicalPayload is required");
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(domain.domainPrefix().getBytes(StandardCharsets.UTF_8));
            md.update((byte) '\n');
            md.update(canonicalPayload.getBytes(StandardCharsets.UTF_8));
            return "sha256:" + HexFormat.of().formatHex(md.digest());
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 algorithm not available", ex);
        }
    }

    /**
     * Computes a digest in {@code targetDomain} from upstream domain digests, rejecting any dependency on
     * a same-or-later topological stage ({@code BND-DIG-002}).
     *
     * @param targetDomain target digest domain
     * @param upstreamDomains upstream digest domains contributing to this digest
     * @param canonicalPayload canonical preimage payload
     * @return {@code sha256:<64-hex>} digest string
     */
    public static String computeAcyclicDerivedDigest(
            DigestDomainKind targetDomain,
            List<DigestDomainKind> upstreamDomains,
            String canonicalPayload
    ) {
        Objects.requireNonNull(targetDomain, "targetDomain is required");
        Objects.requireNonNull(upstreamDomains, "upstreamDomains is required");
        for (DigestDomainKind upstream : upstreamDomains) {
            Objects.requireNonNull(upstream, "upstream domain must not be null");
            if (upstream.topologicalStage() >= targetDomain.topologicalStage()) {
                throw new IllegalArgumentException(
                        "Cyclic or inverted digest dependency: " + targetDomain + " (stage "
                                + targetDomain.topologicalStage() + ") cannot depend on " + upstream
                                + " (stage " + upstream.topologicalStage() + ") (BND-DIG-002)");
            }
        }
        return computeDigest(targetDomain, canonicalPayload);
    }
}
