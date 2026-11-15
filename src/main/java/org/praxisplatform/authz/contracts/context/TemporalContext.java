package org.praxisplatform.authz.contracts.context;

import java.time.Instant;
import java.time.ZoneId;
import java.util.Objects;

/**
 * Server-computed temporal reference attached to an {@link EvaluationContextSnapshot}.
 *
 * @param instant authoritative evaluation instant
 * @param zoneId authoritative evaluation time zone
 */
public record TemporalContext(Instant instant, ZoneId zoneId) {

    /** Validates non-null temporal components. */
    public TemporalContext {
        instant = Objects.requireNonNull(instant, "instant is required");
        zoneId = Objects.requireNonNull(zoneId, "zoneId is required");
    }
}
