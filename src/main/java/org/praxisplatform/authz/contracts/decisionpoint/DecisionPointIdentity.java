package org.praxisplatform.authz.contracts.decisionpoint;

import java.util.Objects;

/**
 * Canonical structured identity and serialized {@code pointKey} of a decision point ({@code DPC-ID-001..015D}).
 *
 * <p>Canonical serialized {@code pointKey} grammar:
 * {@code <kindPrefix>/<resourceOrContextKey>/<operationOrActionKey>} (e.g.
 * {@code resource-operation/human-resources.afastamentos/atualizarSubstituto}).</p>
 *
 * @param pointKey canonical serialized key
 * @param pointKind species of decision point
 * @param serviceKey authoritative service/host key
 * @param resourceKey resource key (or context key for {@code EXPLICIT_DECISION})
 * @param operationOrActionKey canonical {@code operationId}, {@code actionId}, or {@code decisionKey}
 */
public record DecisionPointIdentity(
        String pointKey,
        DecisionPointKind pointKind,
        String serviceKey,
        String resourceKey,
        String operationOrActionKey
) {

    /** Validates canonical {@code pointKey} grammar against {@code pointKind}, {@code resourceKey}, and {@code operationOrActionKey}. */
    public DecisionPointIdentity {
        pointKind = Objects.requireNonNull(pointKind, "pointKind is required");
        serviceKey = requireNonBlank(serviceKey, "serviceKey");
        resourceKey = requireNonBlank(resourceKey, "resourceKey");
        operationOrActionKey = requireNonBlank(operationOrActionKey, "operationOrActionKey");
        pointKey = requireNonBlank(pointKey, "pointKey");
        String expectedKey = formatPointKey(pointKind, resourceKey, operationOrActionKey);
        if (!expectedKey.equals(pointKey)) {
            throw new IllegalArgumentException(
                    "Invalid pointKey '" + pointKey + "'; expected canonical grammar '" + expectedKey + "' (DPC-ID-009)");
        }
    }

    /** Formats the canonical {@code pointKey} for the given components. */
    public static String formatPointKey(
            DecisionPointKind pointKind,
            String resourceKey,
            String operationOrActionKey
    ) {
        Objects.requireNonNull(pointKind, "pointKind is required");
        return pointKind.keyPrefix() + "/" + requireNonBlank(resourceKey, "resourceKey")
                + "/" + requireNonBlank(operationOrActionKey, "operationOrActionKey");
    }

    /** Creates a canonical {@link DecisionPointKind#RESOURCE_OPERATION} identity. */
    public static DecisionPointIdentity resourceOperation(String serviceKey, String resourceKey, String operationId) {
        return new DecisionPointIdentity(
                formatPointKey(DecisionPointKind.RESOURCE_OPERATION, resourceKey, operationId),
                DecisionPointKind.RESOURCE_OPERATION,
                serviceKey,
                resourceKey,
                operationId
        );
    }

    /** Creates a canonical {@link DecisionPointKind#WORKFLOW_ACTION} identity. */
    public static DecisionPointIdentity workflowAction(String serviceKey, String resourceKey, String actionId) {
        return new DecisionPointIdentity(
                formatPointKey(DecisionPointKind.WORKFLOW_ACTION, resourceKey, actionId),
                DecisionPointKind.WORKFLOW_ACTION,
                serviceKey,
                resourceKey,
                actionId
        );
    }

    /** Creates a canonical {@link DecisionPointKind#EXPLICIT_DECISION} identity. */
    public static DecisionPointIdentity explicitDecision(String serviceKey, String contextKey, String decisionKey) {
        return new DecisionPointIdentity(
                formatPointKey(DecisionPointKind.EXPLICIT_DECISION, contextKey, decisionKey),
                DecisionPointKind.EXPLICIT_DECISION,
                serviceKey,
                contextKey,
                decisionKey
        );
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
