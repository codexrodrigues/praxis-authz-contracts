package org.praxisplatform.authz.contracts.binding;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Structured representation of the caller's write intent captured before {@code hydrate*} and
 * {@code PraxisRulesEngine} ({@code CC06}, {@code ENF-FW-001..004B}).
 *
 * @param operationVerb semantic operation verb (e.g. {@code CREATE}, {@code UPDATE}, {@code UPDATE_PARTIAL})
 * @param partialPatch whether omitted fields are untouched ({@code true} for {@code PATCH})
 * @param batchAuthorizationMode batch authorization mode
 * @param transactionCardinality transaction cardinality
 * @param changes immutable list of field-level write changes
 */
public record WriteIntent(
        String operationVerb,
        boolean partialPatch,
        BatchAuthorizationMode batchAuthorizationMode,
        TransactionCardinality transactionCardinality,
        List<WriteFieldChange> changes
) {

    /** Validates non-blank operation verb and normalizes the change list. */
    public WriteIntent {
        Objects.requireNonNull(operationVerb, "operationVerb is required");
        operationVerb = operationVerb.trim();
        if (operationVerb.isEmpty()) {
            throw new IllegalArgumentException("operationVerb must not be blank");
        }
        batchAuthorizationMode = Objects.requireNonNull(batchAuthorizationMode, "batchAuthorizationMode is required");
        transactionCardinality = Objects.requireNonNull(transactionCardinality, "transactionCardinality is required");
        changes = changes == null ? List.of() : List.copyOf(changes);
    }

    /** Returns the unmodifiable set of canonical {@code attributeId}s modified by this write intent. */
    public Set<String> modifiedAttributeIds() {
        return changes.stream()
                .map(WriteFieldChange::attributeId)
                .collect(Collectors.toUnmodifiableSet());
    }
}
