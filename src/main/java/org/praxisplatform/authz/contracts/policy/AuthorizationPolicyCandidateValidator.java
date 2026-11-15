package org.praxisplatform.authz.contracts.policy;

import java.util.Map;
import org.praxisplatform.authz.contracts.context.FactContract;
import org.praxisplatform.authz.contracts.datascope.QueryableResourceProjection;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;

/**
 * Static candidate validator and publication-time selector resolver for
 * {@link AuthorizationPolicyDefinition} ({@code CC01}, {@code CC02}, {@code PDP-COND-001..007}).
 */
public interface AuthorizationPolicyCandidateValidator {

    /** Maximum allowed AST nesting depth ({@code PDP-COND-003}). */
    int MAX_AST_DEPTH = 12;

    /** Maximum allowed AST node count ({@code PDP-COND-003}). */
    int MAX_AST_NODES = 128;

    /** Maximum allowed literal elements in a single {@code in} operator ({@code PDP-COND-003}). */
    int MAX_IN_LITERALS = 64;

    /** Maximum allowed distinct fact references in a condition ({@code PDP-COND-003}). */
    int MAX_REFERENCED_FACTS = 32;

    /**
     * Validates a candidate policy definition against the registered decision points, fact contracts,
     * and queryable resource projections.
     *
     * @param candidate candidate authorization policy definition
     * @param decisionPointsByKey registered decision points keyed by canonical {@code pointKey}
     * @param factContractsById registered fact contracts keyed by {@code factContractId}
     * @param queryProjectionsById registered queryable projections keyed by {@code projectionId}
     * @return validation result containing resolved manifests and diagnostics
     */
    AuthorizationPolicyValidationResult validate(
            AuthorizationPolicyDefinition candidate,
            Map<String, DecisionPointDescriptor> decisionPointsByKey,
            Map<String, FactContract> factContractsById,
            Map<String, QueryableResourceProjection> queryProjectionsById
    );
}
