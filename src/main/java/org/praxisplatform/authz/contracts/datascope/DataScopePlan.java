package org.praxisplatform.authz.contracts.datascope;

import java.util.Objects;

/**
 * Persistence-neutral data scope plan produced for {@code SEARCH} evaluations ({@code CC03},
 * {@code DSP-PLAN-001..004}).
 *
 * @param format canonical wire format identifier ({@link #FORMAT_V1})
 * @param planId unique plan identifier
 * @param decisionPointKey canonical decision point key
 * @param resourceKey canonical resource key
 * @param runtimeRevision provider runtime revision
 * @param policySetDigest provider policy set digest
 * @param factContractDigest governing fact contract digest
 * @param queryProjectionRef queryable resource projection identifier
 * @param queryProjectionDigest queryable resource projection digest
 * @param scopeOutcome {@code ALL}, {@code NONE}, or {@code FILTER}
 * @param pushdownMode {@link PushdownMode#FULL_PUSHDOWN}
 * @param predicateIr predicate tree when {@code scopeOutcome == FILTER}, otherwise {@code null}
 */
public record DataScopePlan(
        String format,
        String planId,
        String decisionPointKey,
        String resourceKey,
        String runtimeRevision,
        String policySetDigest,
        String factContractDigest,
        String queryProjectionRef,
        String queryProjectionDigest,
        DataScopeOutcome scopeOutcome,
        PushdownMode pushdownMode,
        SearchPredicateIr predicateIr
) {

    /** Canonical wire format identifier for {@link DataScopePlan}. */
    public static final String FORMAT_V1 = "praxis.data-scope/v1";

    /** Validates format, digests, and presence/absence of {@code predicateIr} according to {@link DataScopeOutcome}. */
    public DataScopePlan {
        format = requireNonBlank(format, "format");
        if (!FORMAT_V1.equals(format)) {
            throw new IllegalArgumentException("Unsupported DataScopePlan format: " + format);
        }
        planId = requireNonBlank(planId, "planId");
        decisionPointKey = requireNonBlank(decisionPointKey, "decisionPointKey");
        resourceKey = requireNonBlank(resourceKey, "resourceKey");
        runtimeRevision = requireNonBlank(runtimeRevision, "runtimeRevision");
        policySetDigest = requireNonBlank(policySetDigest, "policySetDigest");
        factContractDigest = requireNonBlank(factContractDigest, "factContractDigest");
        queryProjectionRef = requireNonBlank(queryProjectionRef, "queryProjectionRef");
        queryProjectionDigest = requireNonBlank(queryProjectionDigest, "queryProjectionDigest");
        scopeOutcome = Objects.requireNonNull(scopeOutcome, "scopeOutcome is required");
        pushdownMode = Objects.requireNonNull(pushdownMode, "pushdownMode is required");
        if (scopeOutcome == DataScopeOutcome.FILTER && predicateIr == null) {
            throw new IllegalArgumentException("DataScopePlan with scopeOutcome=FILTER must provide predicateIr");
        }
        if (scopeOutcome != DataScopeOutcome.FILTER && predicateIr != null) {
            throw new IllegalArgumentException("DataScopePlan with scopeOutcome=" + scopeOutcome + " must have null predicateIr");
        }
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
