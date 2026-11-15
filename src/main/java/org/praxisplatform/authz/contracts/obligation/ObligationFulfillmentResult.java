package org.praxisplatform.authz.contracts.obligation;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Result of executing an {@link ObligationHandler} at its required {@link ObligationFulfillmentBarrier}
 * ({@code CC10}, {@code ENF-OBL-003}).
 *
 * @param obligationType obligation type identifier
 * @param barrier barrier at which fulfillment was attempted
 * @param fulfilled {@code true} iff the obligation was satisfied
 * @param failureCode non-blank failure code when {@code fulfilled == false}
 * @param auditMetadata sanitized audit metadata
 */
public record ObligationFulfillmentResult(
        String obligationType,
        ObligationFulfillmentBarrier barrier,
        boolean fulfilled,
        String failureCode,
        Map<String, Object> auditMetadata
) {

    /** Validates obligationType, barrier, and failureCode presence when unfulfilled. */
    public ObligationFulfillmentResult {
        Objects.requireNonNull(obligationType, "obligationType is required");
        obligationType = obligationType.trim();
        if (obligationType.isEmpty()) {
            throw new IllegalArgumentException("obligationType must not be blank");
        }
        barrier = Objects.requireNonNull(barrier, "barrier is required");
        if (!fulfilled && (failureCode == null || failureCode.isBlank())) {
            throw new IllegalArgumentException("Unfulfilled obligation result must specify failureCode");
        }
        auditMetadata = auditMetadata == null
                ? Map.of()
                : Collections.unmodifiableMap(new LinkedHashMap<>(auditMetadata));
    }
}
