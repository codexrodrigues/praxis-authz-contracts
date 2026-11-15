package org.praxisplatform.authz.contracts.decisionpoint;

import java.util.Objects;

/**
 * Digest-pinned reference to a {@link DecisionPointDescriptor} ({@code CC05}, {@code CC06}).
 *
 * @param pointKey canonical decision point key
 * @param pointKind decision point species
 * @param serviceKey service/host key
 * @param resourceKey resource or context key
 * @param operationOrActionKey operation, action, or decision key
 * @param descriptorDigest SHA-256 digest of the referenced {@link DecisionPointDescriptor}
 */
public record DecisionPointRef(
        String pointKey,
        DecisionPointKind pointKind,
        String serviceKey,
        String resourceKey,
        String operationOrActionKey,
        String descriptorDigest
) {

    /** Validates canonical identity and non-blank descriptor digest. */
    public DecisionPointRef {
        DecisionPointIdentity validated = new DecisionPointIdentity(
                pointKey, pointKind, serviceKey, resourceKey, operationOrActionKey);
        pointKey = validated.pointKey();
        pointKind = validated.pointKind();
        serviceKey = validated.serviceKey();
        resourceKey = validated.resourceKey();
        operationOrActionKey = validated.operationOrActionKey();
        Objects.requireNonNull(descriptorDigest, "descriptorDigest is required");
        descriptorDigest = descriptorDigest.trim();
        if (descriptorDigest.isEmpty()) {
            throw new IllegalArgumentException("descriptorDigest must not be blank");
        }
    }
}
