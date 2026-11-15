package org.praxisplatform.authz.contracts.obligation;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import org.praxisplatform.authz.contracts.envelope.ObligationDirective;

/**
 * Canonical implementation of {@link ObligationHandlerRegistry} pre-configured with the 4 standard
 * platform obligations ({@code REQUIRE_MFA}, {@code REQUIRE_JUSTIFICATION}, {@code DURABLE_AUDIT_EVIDENCE},
 * {@code WATERMARK}) and enforcing fail-closed barrier semantics ({@code CC10}, {@code ENF-OBL-003}).
 */
public final class DefaultObligationHandlerRegistry implements ObligationHandlerRegistry {

    private final Map<String, ObligationHandler> handlersByType;

    /** Constructs the default registry with the 4 canonical obligation handlers. */
    public DefaultObligationHandlerRegistry() {
        this(defaultHandlers());
    }

    /** Constructs a registry from custom handlers. */
    public DefaultObligationHandlerRegistry(Collection<ObligationHandler> handlers) {
        Objects.requireNonNull(handlers, "handlers is required");
        Map<String, ObligationHandler> map = new LinkedHashMap<>();
        for (ObligationHandler handler : handlers) {
            Objects.requireNonNull(handler, "handler must not be null");
            map.put(handler.obligationType(), handler);
        }
        this.handlersByType = Map.copyOf(map);
    }

    /** Returns the 4 canonical obligation handlers defined in {@code CC10} §5.3.2. */
    public static List<ObligationHandler> defaultHandlers() {
        return List.of(
                new RequireMfaHandler(),
                new RequireJustificationHandler(),
                new DurableAuditEvidenceHandler(),
                new WatermarkHandler()
        );
    }

    @Override
    public Optional<ObligationHandler> findHandler(String obligationType) {
        return Optional.ofNullable(handlersByType.get(obligationType));
    }

    @Override
    public Set<String> listRegisteredTypes() {
        return handlersByType.keySet();
    }

    @Override
    public ObligationMergeOutcome merge(ObligationDirective left, ObligationDirective right) {
        Objects.requireNonNull(left, "left is required");
        Objects.requireNonNull(right, "right is required");
        if (!left.obligationType().equals(right.obligationType())) {
            return new ObligationMergeOutcome(
                    ObligationMergeStatus.OBLIGATION_CONFLICT,
                    null,
                    "AUTHZ_OBLIGATION_TYPE_MISMATCH");
        }
        ObligationHandler handler = handlersByType.get(left.obligationType());
        if (handler == null) {
            return new ObligationMergeOutcome(
                    ObligationMergeStatus.UNKNOWN_OBLIGATION_TYPE,
                    null,
                    "AUTHZ_UNKNOWN_OBLIGATION_TYPE:" + left.obligationType());
        }
        if (!left.fulfillmentBarrier().equals(right.fulfillmentBarrier())
                || !left.trigger().equals(right.trigger())) {
            return new ObligationMergeOutcome(
                    ObligationMergeStatus.OBLIGATION_CONFLICT,
                    null,
                    "AUTHZ_OBLIGATION_TRIGGER_OR_BARRIER_CONFLICT:" + left.obligationType());
        }
        if (!handler.requiredBarrier().name().equals(left.fulfillmentBarrier())) {
            return new ObligationMergeOutcome(
                    ObligationMergeStatus.OBLIGATION_CONFLICT,
                    null,
                    "AUTHZ_OBLIGATION_UNSUPPORTED_BARRIER:" + left.fulfillmentBarrier());
        }
        try {
            ObligationTrigger trigger = ObligationTrigger.valueOf(left.trigger());
            if (!handler.supportedTriggers().contains(trigger)) {
                return new ObligationMergeOutcome(
                        ObligationMergeStatus.OBLIGATION_CONFLICT,
                        null,
                        "AUTHZ_OBLIGATION_UNSUPPORTED_TRIGGER:" + left.trigger());
            }
        } catch (IllegalArgumentException ex) {
            return new ObligationMergeOutcome(
                    ObligationMergeStatus.OBLIGATION_CONFLICT,
                    null,
                    "AUTHZ_OBLIGATION_UNSUPPORTED_TRIGGER:" + left.trigger());
        }
        return handler.merge(left, right);
    }

    /**
     * Enforces {@code ENF-OBL-003}: a {@code PERMIT} disposition can be honored iff every required
     * {@code ON_PERMIT} / {@code ALWAYS} obligation was fulfilled at its barrier.
     *
     * @param results fulfillment results collected across barriers
     * @return {@code true} iff all obligations were fulfilled
     */
    public static boolean canHonorPermitDisposition(Collection<ObligationFulfillmentResult> results) {
        Objects.requireNonNull(results, "results is required");
        for (ObligationFulfillmentResult result : results) {
            if (!result.fulfilled()) {
                return false;
            }
        }
        return true;
    }

    private static final class RequireMfaHandler implements ObligationHandler {
        @Override
        public String obligationType() {
            return "REQUIRE_MFA";
        }

        @Override
        public Set<ObligationTrigger> supportedTriggers() {
            return Set.of(ObligationTrigger.ON_PERMIT);
        }

        @Override
        public ObligationFulfillmentBarrier requiredBarrier() {
            return ObligationFulfillmentBarrier.BEFORE_EXECUTION;
        }

        @Override
        public ObligationMergeOutcome merge(ObligationDirective left, ObligationDirective right) {
            int leftAge = ((Number) left.parameters().getOrDefault("maxAuthAgeSeconds", 300)).intValue();
            int rightAge = ((Number) right.parameters().getOrDefault("maxAuthAgeSeconds", 300)).intValue();
            int mergedAge = Math.min(leftAge, rightAge);
            Set<String> factors = new TreeSet<>();
            addFactors(factors, left.parameters());
            addFactors(factors, right.parameters());
            Map<String, Object> mergedParams = new LinkedHashMap<>();
            mergedParams.put("maxAuthAgeSeconds", mergedAge);
            if (!factors.isEmpty()) {
                mergedParams.put("requiredFactors", List.copyOf(factors));
            }
            return new ObligationMergeOutcome(
                    ObligationMergeStatus.MERGED,
                    new ObligationDirective(
                            obligationType(),
                            left.trigger(),
                            left.fulfillmentBarrier(),
                            mergedParams),
                    null);
        }

        private static void addFactors(Set<String> target, Map<String, Object> params) {
            Object single = params.get("factor");
            if (single instanceof String s && !s.isBlank()) {
                target.add(s.trim());
            }
            Object list = params.get("requiredFactors");
            if (list instanceof Collection<?> col) {
                for (Object item : col) {
                    if (item instanceof String s && !s.isBlank()) {
                        target.add(s.trim());
                    }
                }
            }
        }

        @Override
        public ObligationFulfillmentResult fulfill(ObligationDirective directive, Map<String, Object> executionContext) {
            boolean mfaVerified = Boolean.TRUE.equals(executionContext.get("mfaVerified"));
            int maxAge = ((Number) directive.parameters().getOrDefault("maxAuthAgeSeconds", 300)).intValue();
            int actualAge = ((Number) executionContext.getOrDefault("mfaAuthAgeSeconds", Integer.MAX_VALUE)).intValue();
            boolean ok = mfaVerified && actualAge <= maxAge;
            return new ObligationFulfillmentResult(
                    obligationType(),
                    requiredBarrier(),
                    ok,
                    ok ? null : "OBLIGATION_MFA_REQUIRED_OR_EXPIRED",
                    Map.of("maxAuthAgeSeconds", maxAge));
        }
    }

    private static final class RequireJustificationHandler implements ObligationHandler {
        @Override
        public String obligationType() {
            return "REQUIRE_JUSTIFICATION";
        }

        @Override
        public Set<ObligationTrigger> supportedTriggers() {
            return Set.of(ObligationTrigger.ON_PERMIT);
        }

        @Override
        public ObligationFulfillmentBarrier requiredBarrier() {
            return ObligationFulfillmentBarrier.BEFORE_EXECUTION;
        }

        @Override
        public ObligationMergeOutcome merge(ObligationDirective left, ObligationDirective right) {
            int leftMin = ((Number) left.parameters().getOrDefault("minLength", 10)).intValue();
            int rightMin = ((Number) right.parameters().getOrDefault("minLength", 10)).intValue();
            int mergedMin = Math.max(leftMin, rightMin);
            return new ObligationMergeOutcome(
                    ObligationMergeStatus.MERGED,
                    new ObligationDirective(
                            obligationType(),
                            left.trigger(),
                            left.fulfillmentBarrier(),
                            Map.of("minLength", mergedMin)),
                    null);
        }

        @Override
        public ObligationFulfillmentResult fulfill(ObligationDirective directive, Map<String, Object> executionContext) {
            int minLength = ((Number) directive.parameters().getOrDefault("minLength", 10)).intValue();
            Object justificationObj = executionContext.get("justificationText");
            String text = justificationObj instanceof String s ? s.trim() : "";
            boolean ok = text.length() >= minLength;
            return new ObligationFulfillmentResult(
                    obligationType(),
                    requiredBarrier(),
                    ok,
                    ok ? null : "OBLIGATION_JUSTIFICATION_TOO_SHORT",
                    Map.of("requiredMinLength", minLength, "providedLength", text.length()));
        }
    }

    private static final class DurableAuditEvidenceHandler implements ObligationHandler {
        @Override
        public String obligationType() {
            return "DURABLE_AUDIT_EVIDENCE";
        }

        @Override
        public Set<ObligationTrigger> supportedTriggers() {
            return Set.of(ObligationTrigger.ON_PERMIT, ObligationTrigger.ON_DENY, ObligationTrigger.ALWAYS);
        }

        @Override
        public ObligationFulfillmentBarrier requiredBarrier() {
            return ObligationFulfillmentBarrier.BEFORE_COMMIT_OUTBOX;
        }

        @Override
        public ObligationMergeOutcome merge(ObligationDirective left, ObligationDirective right) {
            Set<String> categories = new TreeSet<>();
            addCategories(categories, left.parameters());
            addCategories(categories, right.parameters());
            return new ObligationMergeOutcome(
                    ObligationMergeStatus.MERGED,
                    new ObligationDirective(
                            obligationType(),
                            left.trigger(),
                            left.fulfillmentBarrier(),
                            Map.of("auditCategories", List.copyOf(categories))),
                    null);
        }

        @Override
        public ObligationFulfillmentResult fulfill(ObligationDirective directive, Map<String, Object> executionContext) {
            boolean outboxPersisted = Boolean.TRUE.equals(executionContext.get("auditOutboxPersisted"));
            return new ObligationFulfillmentResult(
                    obligationType(),
                    requiredBarrier(),
                    outboxPersisted,
                    outboxPersisted ? null : "OBLIGATION_AUDIT_OUTBOX_WRITE_FAILED",
                    directive.parameters());
        }

        private static void addCategories(Set<String> target, Map<String, Object> params) {
            Object single = params.get("auditCategory");
            if (single instanceof String s && !s.isBlank()) {
                target.add(s.trim());
            }
            Object list = params.get("auditCategories");
            if (list instanceof Collection<?> col) {
                for (Object item : col) {
                    if (item instanceof String s && !s.isBlank()) {
                        target.add(s.trim());
                    }
                }
            }
        }
    }

    private static final class WatermarkHandler implements ObligationHandler {
        @Override
        public String obligationType() {
            return "WATERMARK";
        }

        @Override
        public Set<ObligationTrigger> supportedTriggers() {
            return Set.of(ObligationTrigger.ON_PERMIT);
        }

        @Override
        public ObligationFulfillmentBarrier requiredBarrier() {
            return ObligationFulfillmentBarrier.BEFORE_DISCLOSURE;
        }

        @Override
        public ObligationMergeOutcome merge(ObligationDirective left, ObligationDirective right) {
            Set<String> stamps = new TreeSet<>();
            addStamp(stamps, left.parameters());
            addStamp(stamps, right.parameters());
            return new ObligationMergeOutcome(
                    ObligationMergeStatus.MERGED,
                    new ObligationDirective(
                            obligationType(),
                            left.trigger(),
                            left.fulfillmentBarrier(),
                            Map.of("stamps", List.copyOf(stamps))),
                    null);
        }

        @Override
        public ObligationFulfillmentResult fulfill(ObligationDirective directive, Map<String, Object> executionContext) {
            boolean watermarkApplied = Boolean.TRUE.equals(executionContext.get("watermarkApplied"));
            return new ObligationFulfillmentResult(
                    obligationType(),
                    requiredBarrier(),
                    watermarkApplied,
                    watermarkApplied ? null : "OBLIGATION_WATERMARK_NOT_APPLIED",
                    directive.parameters());
        }

        private static void addStamp(Set<String> target, Map<String, Object> params) {
            Object single = params.get("stamp");
            if (single instanceof String s && !s.isBlank()) {
                target.add(s.trim());
            }
            Object list = params.get("stamps");
            if (list instanceof Collection<?> col) {
                for (Object item : col) {
                    if (item instanceof String s && !s.isBlank()) {
                        target.add(s.trim());
                    }
                }
            }
        }
    }
}
