package org.praxisplatform.authz.contracts.envelope;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Verifiable obligation directive attached to an authorization decision ({@code CC07}, {@code CC10}).
 *
 * @param obligationType registered obligation type identifier
 * @param trigger activation trigger ({@code ON_PERMIT}, {@code ON_DENY}, {@code ALWAYS})
 * @param fulfillmentBarrier required barrier ({@code BEFORE_EXECUTION}, {@code BEFORE_COMMIT_OUTBOX}, {@code BEFORE_DISCLOSURE})
 * @param parameters immutable obligation parameters
 */
public record ObligationDirective(
        String obligationType,
        String trigger,
        String fulfillmentBarrier,
        Map<String, Object> parameters
) {

    /** Validates non-blank type, trigger, and barrier and wraps parameters as unmodifiable. */
    public ObligationDirective {
        obligationType = requireNonBlank(obligationType, "obligationType");
        trigger = requireNonBlank(trigger, "trigger");
        fulfillmentBarrier = requireNonBlank(fulfillmentBarrier, "fulfillmentBarrier");
        parameters = parameters == null
                ? Map.of()
                : Collections.unmodifiableMap(new LinkedHashMap<>(parameters));
    }

    private static String requireNonBlank(String value, String field) {
        Objects.requireNonNull(value, field + " is required");
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return trimmed;
    }
}
