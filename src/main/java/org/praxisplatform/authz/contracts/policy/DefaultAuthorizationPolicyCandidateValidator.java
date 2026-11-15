package org.praxisplatform.authz.contracts.policy;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import org.praxisplatform.authz.contracts.context.ContextEvaluationPhase;
import org.praxisplatform.authz.contracts.context.FactContract;
import org.praxisplatform.authz.contracts.context.FactDescriptor;
import org.praxisplatform.authz.contracts.context.FactPresenceModel;
import org.praxisplatform.authz.contracts.datascope.QueryableResourceProjection;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointRef;
import org.praxisplatform.authz.contracts.decisionpoint.EnforcementCapability;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.digest.CanonicalDigestCalculator;
import org.praxisplatform.authz.contracts.digest.DigestDomainKind;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;
import org.praxisplatform.authz.contracts.envelope.ObligationDirective;
import org.praxisplatform.authz.contracts.masking.DefaultMaskStrategyRegistry;
import org.praxisplatform.authz.contracts.masking.MaskStrategyRegistry;
import org.praxisplatform.authz.contracts.obligation.DefaultObligationHandlerRegistry;
import org.praxisplatform.authz.contracts.obligation.ObligationHandlerRegistry;
import org.praxisplatform.authz.contracts.obligation.ObligationMergeOutcome;
import org.praxisplatform.authz.contracts.obligation.ObligationMergeStatus;

/**
 * Canonical deterministic implementation of {@link AuthorizationPolicyCandidateValidator} ({@code CC01}, {@code CC02}).
 */
public final class DefaultAuthorizationPolicyCandidateValidator implements AuthorizationPolicyCandidateValidator {

    private static final Set<String> ALLOWED_OPERATORS = Set.of(
            "and", "or", "!", "==", "!=", "<", "<=", ">", ">=",
            "in", "is_null", "is_not_null", "starts_with", "ends_with", "text_contains", "var"
    );

    private final MaskStrategyRegistry maskStrategyRegistry;
    private final ObligationHandlerRegistry obligationHandlerRegistry;

    /** Creates a validator backed by the canonical default masking and obligation registries. */
    public DefaultAuthorizationPolicyCandidateValidator() {
        this(new DefaultMaskStrategyRegistry(), new DefaultObligationHandlerRegistry());
    }

    /** Creates a validator backed by custom host masking and obligation registries. */
    public DefaultAuthorizationPolicyCandidateValidator(
            MaskStrategyRegistry maskStrategyRegistry,
            ObligationHandlerRegistry obligationHandlerRegistry
    ) {
        this.maskStrategyRegistry = Objects.requireNonNull(maskStrategyRegistry, "maskStrategyRegistry is required");
        this.obligationHandlerRegistry = Objects.requireNonNull(obligationHandlerRegistry, "obligationHandlerRegistry is required");
    }

    @Override
    public AuthorizationPolicyValidationResult validate(
            AuthorizationPolicyDefinition candidate,
            Map<String, DecisionPointDescriptor> decisionPointsByKey,
            Map<String, FactContract> factContractsById,
            Map<String, QueryableResourceProjection> queryProjectionsById
    ) {
        Objects.requireNonNull(candidate, "candidate is required");
        Objects.requireNonNull(decisionPointsByKey, "decisionPointsByKey is required");
        Objects.requireNonNull(factContractsById, "factContractsById is required");
        Objects.requireNonNull(queryProjectionsById, "queryProjectionsById is required");

        List<PolicyValidationDiagnostic> diagnostics = new ArrayList<>();
        List<TargetResolutionManifest> resolvedTargets = new ArrayList<>();
        List<DecisionPointDescriptor> matchedDescriptors = new ArrayList<>();

        for (int i = 0; i < candidate.targets().size(); i++) {
            PolicyTargetSpec target = candidate.targets().get(i);
            String pointer = "/targets/" + i;
            List<DecisionPointDescriptor> matches = resolveTargetDescriptors(
                    target, decisionPointsByKey, diagnostics, pointer);
            if (!matches.isEmpty()) {
                matchedDescriptors.addAll(matches);
                List<DecisionPointRef> refs = matches.stream()
                        .sorted(Comparator.comparing(d -> d.identity().pointKey()))
                        .map(DecisionPointDescriptor::toRef)
                        .toList();
                String selectorDigest = CanonicalDigestCalculator.computeDigest(
                        DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, target.toCanonicalPreimage());
                String resolvedSetDigest = CanonicalDigestCalculator.computeDigest(
                        DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, refs.toString());
                resolvedTargets.add(new TargetResolutionManifest(
                        target.targetId(), selectorDigest, refs, resolvedSetDigest));
            }
        }

        // Collect governing FactContracts and QueryableResourceProjections from matched decision points
        Map<String, FactDescriptor> allFactsByPath = new LinkedHashMap<>();
        Set<String> queryableFieldPaths = new LinkedHashSet<>();
        for (DecisionPointDescriptor dp : matchedDescriptors) {
            FactContract fc = factContractsById.get(dp.factContractRef().factContractId());
            if (fc == null) {
                diagnostics.add(new PolicyValidationDiagnostic(
                        "AUTHZ_FACT_CONTRACT_NOT_FOUND",
                        "ERROR",
                        null,
                        "/targets",
                        "Referenced FactContract '" + dp.factContractRef().factContractId() + "' not found"));
            } else {
                if (!fc.factContractDigest().equals(dp.factContractRef().factContractDigest())) {
                    diagnostics.add(new PolicyValidationDiagnostic(
                            "AUTHZ_FACT_CONTRACT_DIGEST_MISMATCH",
                            "ERROR",
                            null,
                            "/targets",
                            "FactContract digest mismatch for '" + fc.factContractId() + "'"));
                }
                allFactsByPath.putAll(fc.descriptorsByPath());
            }
            if (dp.queryProjectionRef() != null) {
                QueryableResourceProjection qp = queryProjectionsById.get(dp.queryProjectionRef().projectionId());
                if (qp == null) {
                    diagnostics.add(new PolicyValidationDiagnostic(
                            "AUTHZ_QUERY_PROJECTION_NOT_FOUND",
                            "ERROR",
                            null,
                            "/targets",
                            "Referenced QueryableResourceProjection '" + dp.queryProjectionRef().projectionId() + "' not found"));
                } else {
                    if (!qp.projectionDigest().equals(dp.queryProjectionRef().projectionDigest())) {
                        diagnostics.add(new PolicyValidationDiagnostic(
                                "AUTHZ_QUERY_PROJECTION_DIGEST_MISMATCH",
                                "ERROR",
                                null,
                                "/targets",
                                "QueryableResourceProjection digest mismatch for '" + qp.projectionId() + "'"));
                    }
                    queryableFieldPaths.addAll(qp.fieldsByPath().keySet());
                }
            }
        }

        // Validate factRequirements
        for (int i = 0; i < candidate.factRequirements().size(); i++) {
            PolicyFactRequirement req = candidate.factRequirements().get(i);
            if (!allFactsByPath.containsKey(req.factPath())) {
                diagnostics.add(new PolicyValidationDiagnostic(
                        "AUTHZ_UNKNOWN_REQUIRED_FACT",
                        "ERROR",
                        null,
                        "/factRequirements/" + i + "/factPath",
                        "Required factPath '" + req.factPath() + "' does not exist in governing FactContract"));
            }
        }

        Map<String, FieldResolutionManifest> resolvedSelectors = new LinkedHashMap<>();
        for (int rIdx = 0; rIdx < candidate.rules().size(); rIdx++) {
            AuthorizationPolicyRule rule = candidate.rules().get(rIdx);
            String rulePtr = "/rules/" + rIdx;
            boolean ruleSupportsSearch = rule.evaluationModes().contains(EvaluationMode.SEARCH);

            validateConditionAst(
                    rule.when(),
                    ruleSupportsSearch,
                    rule.ruleId(),
                    rulePtr + "/when",
                    allFactsByPath,
                    queryableFieldPaths,
                    diagnostics);

            AuthorizationRuleContributions contrib = rule.contributions();
            validateRuleCapabilitiesAgainstDescriptors(rule, rulePtr, matchedDescriptors, diagnostics);

            if (contrib.dataScope() != null) {
                validateConditionAst(
                        contrib.dataScope().resourceCondition(),
                        true,
                        rule.ruleId(),
                        rulePtr + "/contributions/dataScope/resourceCondition",
                        allFactsByPath,
                        queryableFieldPaths,
                        diagnostics);
            }

            for (FieldUseContributionSpec fu : contrib.fieldUse()) {
                resolveFieldSelector(fu.fieldSelector(), rule.ruleId(), rulePtr + "/contributions/fieldUse",
                        allFactsByPath.values(), resolvedSelectors, diagnostics);
            }
            for (FieldWriteContributionSpec fw : contrib.fieldWrite()) {
                resolveFieldSelector(fw.fieldSelector(), rule.ruleId(), rulePtr + "/contributions/fieldWrite",
                        allFactsByPath.values(), resolvedSelectors, diagnostics);
            }
            for (MaskContributionSpec m : contrib.mask()) {
                Set<String> matchedAttrs = resolveFieldSelector(m.fieldSelector(), rule.ruleId(),
                        rulePtr + "/contributions/mask", allFactsByPath.values(), resolvedSelectors, diagnostics);
                validateMaskContribution(m, matchedAttrs, rule.ruleId(), rulePtr + "/contributions/mask",
                        allFactsByPath.values(), diagnostics);
            }
            for (ObligationDirective ob : rule.obligations()) {
                validateObligationDirective(ob, rule.ruleId(), rulePtr + "/obligations", diagnostics);
            }
        }

        boolean valid = diagnostics.stream().noneMatch(d -> "ERROR".equals(d.severity()));
        return new AuthorizationPolicyValidationResult(valid, resolvedTargets, resolvedSelectors, diagnostics);
    }

    private void validateMaskContribution(
            MaskContributionSpec maskSpec,
            Set<String> matchedAttributes,
            String ruleId,
            String pointer,
            Collection<FactDescriptor> descriptors,
            List<PolicyValidationDiagnostic> diagnostics
    ) {
        if (maskStrategyRegistry.findById(maskSpec.strategyId()).isEmpty()) {
            diagnostics.add(new PolicyValidationDiagnostic(
                    "AUTHZ_UNKNOWN_MASK_STRATEGY",
                    "ERROR",
                    ruleId,
                    pointer,
                    "Unknown mask strategy '" + maskSpec.strategyId() + "' (MSK-CAT-001)"));
            return;
        }
        for (FactDescriptor fd : descriptors) {
            if (fd.attributeId() != null && matchedAttributes.contains(fd.attributeId())) {
                MaskDirective sample = new MaskDirective(fd.attributeId(), maskSpec.strategyId(), maskSpec.parameters());
                boolean nullable = fd.presenceModel() == FactPresenceModel.MAY_BE_ABSENT;
                if (!maskStrategyRegistry.isCompatibleWithTargetField(sample, fd.valueType(), nullable)) {
                    diagnostics.add(new PolicyValidationDiagnostic(
                            "AUTHZ_INCOMPATIBLE_MASK_STRATEGY",
                            "ERROR",
                            ruleId,
                            pointer,
                            "Mask strategy '" + maskSpec.strategyId() + "' is incompatible with attribute '"
                                    + fd.attributeId() + "' of type " + fd.valueType() + " (nullable=" + nullable + ")"));
                }
            }
        }
    }

    private void validateObligationDirective(
            ObligationDirective directive,
            String ruleId,
            String pointer,
            List<PolicyValidationDiagnostic> diagnostics
    ) {
        if (obligationHandlerRegistry.findHandler(directive.obligationType()).isEmpty()) {
            diagnostics.add(new PolicyValidationDiagnostic(
                    "AUTHZ_UNKNOWN_OBLIGATION_TYPE",
                    "ERROR",
                    ruleId,
                    pointer,
                    "Unknown obligation type '" + directive.obligationType() + "' (OBL-REG-001)"));
            return;
        }
        ObligationMergeOutcome selfCheck = obligationHandlerRegistry.merge(directive, directive);
        if (selfCheck.status() != ObligationMergeStatus.MERGED) {
            diagnostics.add(new PolicyValidationDiagnostic(
                    "AUTHZ_INVALID_OBLIGATION_DIRECTIVE",
                    "ERROR",
                    ruleId,
                    pointer,
                    "Invalid obligation directive '" + directive.obligationType() + "': " + selfCheck.diagnosticCode()));
        }
    }

    private void validateRuleCapabilitiesAgainstDescriptors(
            AuthorizationPolicyRule rule,
            String rulePtr,
            List<DecisionPointDescriptor> matchedDescriptors,
            List<PolicyValidationDiagnostic> diagnostics
    ) {
        AuthorizationRuleContributions contrib = rule.contributions();
        for (DecisionPointDescriptor dp : matchedDescriptors) {
            if (!dp.evaluationModes().containsAll(rule.evaluationModes())) {
                diagnostics.add(new PolicyValidationDiagnostic(
                        "AUTHZ_RULE_MODE_NOT_SUPPORTED_BY_DECISION_POINT",
                        "ERROR",
                        rule.ruleId(),
                        rulePtr + "/evaluationModes",
                        "Decision point '" + dp.identity().pointKey()
                                + "' does not support all rule evaluationModes: " + rule.evaluationModes()));
            }
            if (contrib.dataScope() != null && !dp.supportedCapabilities().contains(EnforcementCapability.DATA_SCOPE)) {
                diagnostics.add(new PolicyValidationDiagnostic(
                        "AUTHZ_CAPABILITY_NOT_SUPPORTED_BY_DECISION_POINT",
                        "ERROR",
                        rule.ruleId(),
                        rulePtr + "/contributions/dataScope",
                        "Decision point '" + dp.identity().pointKey() + "' does not support DATA_SCOPE"));
            }
            if (!contrib.fieldUse().isEmpty()) {
                if (!dp.supportedCapabilities().contains(EnforcementCapability.FIELD_USE)) {
                    diagnostics.add(new PolicyValidationDiagnostic(
                            "AUTHZ_CAPABILITY_NOT_SUPPORTED_BY_DECISION_POINT",
                            "ERROR",
                            rule.ruleId(),
                            rulePtr + "/contributions/fieldUse",
                            "Decision point '" + dp.identity().pointKey() + "' does not support FIELD_USE"));
                } else {
                    for (FieldUseContributionSpec fu : contrib.fieldUse()) {
                        if (!dp.supportedFieldUseCategories().containsAll(fu.categories())) {
                            diagnostics.add(new PolicyValidationDiagnostic(
                                    "AUTHZ_FIELD_USE_CATEGORY_NOT_SUPPORTED_BY_DECISION_POINT",
                                    "ERROR",
                                    rule.ruleId(),
                                    rulePtr + "/contributions/fieldUse",
                                    "Decision point '" + dp.identity().pointKey()
                                            + "' does not support all requested FieldUseCategories: " + fu.categories()));
                        }
                    }
                }
            }
            if (!contrib.fieldWrite().isEmpty() && !dp.supportedCapabilities().contains(EnforcementCapability.FIELD_WRITE)) {
                diagnostics.add(new PolicyValidationDiagnostic(
                        "AUTHZ_CAPABILITY_NOT_SUPPORTED_BY_DECISION_POINT",
                        "ERROR",
                        rule.ruleId(),
                        rulePtr + "/contributions/fieldWrite",
                        "Decision point '" + dp.identity().pointKey() + "' does not support FIELD_WRITE"));
            }
            if (!contrib.mask().isEmpty() && !dp.supportedCapabilities().contains(EnforcementCapability.MASK)) {
                diagnostics.add(new PolicyValidationDiagnostic(
                        "AUTHZ_CAPABILITY_NOT_SUPPORTED_BY_DECISION_POINT",
                        "ERROR",
                        rule.ruleId(),
                        rulePtr + "/contributions/mask",
                        "Decision point '" + dp.identity().pointKey() + "' does not support MASK"));
            }
            if (!rule.obligations().isEmpty() && !dp.obligationSupport().supportedTypes().isEmpty()) {
                for (ObligationDirective ob : rule.obligations()) {
                    if (!dp.obligationSupport().supportedTypes().contains(ob.obligationType())
                            || !dp.obligationSupport().supportedFulfillmentProfiles().contains(ob.fulfillmentBarrier())) {
                        diagnostics.add(new PolicyValidationDiagnostic(
                                "AUTHZ_OBLIGATION_NOT_SUPPORTED_BY_DECISION_POINT",
                                "ERROR",
                                rule.ruleId(),
                                rulePtr + "/obligations",
                                "Decision point '" + dp.identity().pointKey() + "' does not support obligation '"
                                        + ob.obligationType() + "' at barrier '" + ob.fulfillmentBarrier() + "'"));
                    }
                }
            }
        }
    }

    private List<DecisionPointDescriptor> resolveTargetDescriptors(
            PolicyTargetSpec target,
            Map<String, DecisionPointDescriptor> decisionPointsByKey,
            List<PolicyValidationDiagnostic> diagnostics,
            String pointer
    ) {
        if (target.kind() == PolicyTargetSpecKind.EXACT) {
            DecisionPointDescriptor dp = decisionPointsByKey.get(target.pointKey());
            if (dp == null) {
                diagnostics.add(new PolicyValidationDiagnostic(
                        "AUTHZ_TARGET_POINT_NOT_FOUND",
                        "ERROR",
                        null,
                        pointer + "/pointKey",
                        "Decision point '" + target.pointKey() + "' not found in catalog"));
                return List.of();
            }
            if (!dp.descriptorDigest().equals(target.expectedDescriptorDigest())) {
                diagnostics.add(new PolicyValidationDiagnostic(
                        "AUTHZ_TARGET_DIGEST_MISMATCH",
                        "ERROR",
                        null,
                        pointer + "/expectedDescriptorDigest",
                        "Descriptor digest mismatch for '" + target.pointKey() + "'"));
                return List.of();
            }
            if (!dp.evaluationModes().containsAll(target.evaluationModes())) {
                diagnostics.add(new PolicyValidationDiagnostic(
                        "AUTHZ_TARGET_MODE_NOT_SUPPORTED",
                        "ERROR",
                        null,
                        pointer + "/evaluationModes",
                        "Decision point '" + target.pointKey() + "' does not support target evaluationModes "
                                + target.evaluationModes()));
                return List.of();
            }
            return List.of(dp);
        }

        List<DecisionPointDescriptor> matches = new ArrayList<>();
        for (DecisionPointDescriptor dp : decisionPointsByKey.values()) {
            boolean kindMatch = target.selectorPointKinds().isEmpty()
                    || target.selectorPointKinds().contains(dp.identity().pointKind());
            boolean resourceMatch = target.selectorResourceKeys().isEmpty()
                    || target.selectorResourceKeys().contains(dp.identity().resourceKey());
            boolean verbMatch = target.selectorOperationVerbs().isEmpty()
                    || target.selectorOperationVerbs().contains(dp.operationVerb());
            boolean modeMatch = dp.evaluationModes().containsAll(target.evaluationModes());
            if (kindMatch && resourceMatch && verbMatch && modeMatch) {
                matches.add(dp);
            }
        }
        if (matches.isEmpty()) {
            diagnostics.add(new PolicyValidationDiagnostic(
                    "AUTHZ_TARGET_SELECTOR_EMPTY_RESOLUTION",
                    "ERROR",
                    null,
                    pointer,
                    "Selector target '" + target.targetId() + "' resolved to 0 decision points (PDP-TGT-005)"));
        }
        return matches;
    }

    private Set<String> resolveFieldSelector(
            PolicyFieldSelector selector,
            String ruleId,
            String pointer,
            Collection<FactDescriptor> descriptors,
            Map<String, FieldResolutionManifest> resolvedSelectors,
            List<PolicyValidationDiagnostic> diagnostics
    ) {
        Set<String> knownAttributeIds = new LinkedHashSet<>();
        for (FactDescriptor fd : descriptors) {
            if (fd.attributeId() != null) {
                knownAttributeIds.add(fd.attributeId());
            }
        }

        Set<String> matchedAttributes = new TreeSet<>();
        if (selector.kind() == FieldSelectorKind.EXACT) {
            for (String attrId : selector.attributeIds()) {
                if (knownAttributeIds.contains(attrId)) {
                    matchedAttributes.add(attrId);
                } else {
                    diagnostics.add(new PolicyValidationDiagnostic(
                            "AUTHZ_FIELD_SELECTOR_UNKNOWN_ATTRIBUTE",
                            "ERROR",
                            ruleId,
                            pointer,
                            "EXACT field selector references unknown attributeId '" + attrId + "' (PDP-FLD-002)"));
                }
            }
        } else {
            for (FactDescriptor fd : descriptors) {
                if (fd.attributeId() == null) {
                    continue;
                }
                if (selector.kind() == FieldSelectorKind.GOVERNANCE) {
                    boolean clsOk = selector.classifications().isEmpty()
                            || (fd.classification() != null && selector.classifications().contains(fd.classification()));
                    boolean catOk = selector.dataCategories().isEmpty()
                            || (fd.dataCategory() != null && selector.dataCategories().contains(fd.dataCategory()));
                    boolean tagOk = selector.complianceTags().isEmpty()
                            || fd.complianceTags().containsAll(selector.complianceTags());
                    boolean lpOk = selector.legalPurposes().isEmpty()
                            || (fd.legalPurpose() != null && selector.legalPurposes().contains(fd.legalPurpose()));
                    if (clsOk && catOk && tagOk && lpOk) {
                        matchedAttributes.add(fd.attributeId());
                    }
                } else if (selector.kind() == FieldSelectorKind.LINEAGE) {
                    boolean ownerOk = selector.lineageDomainOwner() == null
                            || selector.lineageDomainOwner().isBlank()
                            || fd.attributeId().startsWith(selector.lineageDomainOwner() + ".");
                    boolean prefixOk = selector.lineageAttributePrefix() == null
                            || selector.lineageAttributePrefix().isBlank()
                            || fd.attributeId().startsWith(selector.lineageAttributePrefix());
                    if (ownerOk && prefixOk) {
                        matchedAttributes.add(fd.attributeId());
                    }
                } else if (selector.kind() == FieldSelectorKind.CONCEPT) {
                    String conceptKey = selector.semanticConceptKey();
                    if (conceptKey != null && !conceptKey.isBlank()
                            && (conceptKey.equals(fd.resourceFactId())
                                    || fd.attributeId().endsWith("." + conceptKey)
                                    || fd.attributeId().equals(conceptKey))) {
                        matchedAttributes.add(fd.attributeId());
                    }
                }
            }
        }

        if (matchedAttributes.isEmpty()) {
            diagnostics.add(new PolicyValidationDiagnostic(
                    "AUTHZ_FIELD_SELECTOR_EMPTY_RESOLUTION",
                    "ERROR",
                    ruleId,
                    pointer,
                    "Field selector resolved to 0 attributes (PDP-FLD-005)"));
            return Set.of();
        }
        String selectorDigest = CanonicalDigestCalculator.computeDigest(
                DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, selector.toCanonicalPreimage());
        String resolvedSetDigest = CanonicalDigestCalculator.computeDigest(
                DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, matchedAttributes.toString());
        resolvedSelectors.put(
                selectorDigest,
                new FieldResolutionManifest(selectorDigest, matchedAttributes, resolvedSetDigest));
        return matchedAttributes;
    }

    private void validateConditionAst(
            AuthorizationSourceCondition condition,
            boolean ruleSupportsSearch,
            String ruleId,
            String pointer,
            Map<String, FactDescriptor> allFactsByPath,
            Set<String> queryableFieldPaths,
            List<PolicyValidationDiagnostic> diagnostics
    ) {
        AstMetrics metrics = new AstMetrics();
        Set<String> referencedFacts = new LinkedHashSet<>();
        inspectAstNode(
                condition.expression(),
                1,
                condition.profile(),
                ruleSupportsSearch,
                ruleId,
                pointer,
                allFactsByPath,
                queryableFieldPaths,
                metrics,
                referencedFacts,
                diagnostics);

        if (metrics.maxDepth > MAX_AST_DEPTH) {
            diagnostics.add(new PolicyValidationDiagnostic(
                    "AUTHZ_AST_DEPTH_LIMIT_EXCEEDED",
                    "ERROR",
                    ruleId,
                    pointer,
                    "Condition AST depth " + metrics.maxDepth + " exceeds MAX_AST_DEPTH=" + MAX_AST_DEPTH));
        }
        if (metrics.nodeCount > MAX_AST_NODES) {
            diagnostics.add(new PolicyValidationDiagnostic(
                    "AUTHZ_AST_NODE_LIMIT_EXCEEDED",
                    "ERROR",
                    ruleId,
                    pointer,
                    "Condition AST node count " + metrics.nodeCount + " exceeds MAX_AST_NODES=" + MAX_AST_NODES));
        }
        if (referencedFacts.size() > MAX_REFERENCED_FACTS) {
            diagnostics.add(new PolicyValidationDiagnostic(
                    "AUTHZ_AST_REFERENCED_FACTS_LIMIT_EXCEEDED",
                    "ERROR",
                    ruleId,
                    pointer,
                    "Condition references " + referencedFacts.size()
                            + " distinct facts, exceeding MAX_REFERENCED_FACTS=" + MAX_REFERENCED_FACTS));
        }
    }

    private void inspectAstNode(
            Object node,
            int depth,
            ConditionProfileKind profile,
            boolean ruleSupportsSearch,
            String ruleId,
            String pointer,
            Map<String, FactDescriptor> allFactsByPath,
            Set<String> queryableFieldPaths,
            AstMetrics metrics,
            Set<String> referencedFacts,
            List<PolicyValidationDiagnostic> diagnostics
    ) {
        metrics.nodeCount++;
        if (depth > metrics.maxDepth) {
            metrics.maxDepth = depth;
        }

        if (node instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                String op = String.valueOf(entry.getKey());
                Object val = entry.getValue();
                if (!ALLOWED_OPERATORS.contains(op)) {
                    diagnostics.add(new PolicyValidationDiagnostic(
                            "AUTHZ_AST_FORBIDDEN_OPERATOR",
                            "ERROR",
                            ruleId,
                            pointer,
                            "Forbidden or unsupported operator '" + op + "' in condition AST (PDP-COND-003)"));
                    continue;
                }
                if ("var".equals(op) && val instanceof String factPath) {
                    referencedFacts.add(factPath);
                    FactDescriptor fd = allFactsByPath.get(factPath);
                    if (fd == null) {
                        diagnostics.add(new PolicyValidationDiagnostic(
                                "AUTHZ_UNKNOWN_FACT_REFERENCE",
                                "ERROR",
                                ruleId,
                                pointer,
                                "Condition references unknown fact '" + factPath + "'"));
                    } else if (profile == ConditionProfileKind.AUTHORIZATION_SEARCH_SOURCE_V1) {
                        if (factPath.startsWith("transition.")) {
                            diagnostics.add(new PolicyValidationDiagnostic(
                                    "AUTHZ_SEARCH_TRANSITION_FACT_FORBIDDEN",
                                    "ERROR",
                                    ruleId,
                                    pointer,
                                    "Transition fact '" + factPath
                                            + "' is forbidden in authorization-search-source/v1 (DSP-GEN-003)"));
                        } else if (factPath.startsWith("resource.")
                                && (!fd.searchQueryable() || !queryableFieldPaths.contains(factPath))) {
                            diagnostics.add(new PolicyValidationDiagnostic(
                                    "AUTHZ_SEARCH_FACT_NOT_QUERYABLE",
                                    "ERROR",
                                    ruleId,
                                    pointer,
                                    "Resource fact '" + factPath
                                            + "' is not searchQueryable in QueryableResourceProjection (CTX-CONTRACT-005)"));
                        }
                    } else if (profile == ConditionProfileKind.AUTHORIZATION_TARGET_V1
                            && ruleSupportsSearch
                            && !fd.availableInPhases().contains(ContextEvaluationPhase.ADMISSION)) {
                        diagnostics.add(new PolicyValidationDiagnostic(
                                "AUTHZ_SEARCH_WHEN_REFERENCES_TARGET_FACT",
                                "ERROR",
                                ruleId,
                                pointer,
                                "Rule enabled for SEARCH mode cannot reference TARGET-only fact '"
                                        + factPath + "' in 'when' condition (CTX-PHASE-002)"));
                    }
                    continue;
                }
                if ("in".equals(op) && val instanceof List<?> inArgs && inArgs.size() == 2) {
                    Object lhs = inArgs.get(0);
                    Object rhs = inArgs.get(1);
                    inspectAstNode(
                            lhs,
                            depth + 1,
                            profile,
                            ruleSupportsSearch,
                            ruleId,
                            pointer,
                            allFactsByPath,
                            queryableFieldPaths,
                            metrics,
                            referencedFacts,
                            diagnostics);
                    if (rhs instanceof List<?> literalList) {
                        metrics.nodeCount++;
                        if (literalList.size() > MAX_IN_LITERALS) {
                            diagnostics.add(new PolicyValidationDiagnostic(
                                    "AUTHZ_AST_IN_LIST_LIMIT_EXCEEDED",
                                    "ERROR",
                                    ruleId,
                                    pointer,
                                    "'in' literal list size " + literalList.size()
                                            + " exceeds MAX_IN_LITERALS=" + MAX_IN_LITERALS));
                        }
                    } else {
                        inspectAstNode(
                                rhs,
                                depth + 1,
                                profile,
                                ruleSupportsSearch,
                                ruleId,
                                pointer,
                                allFactsByPath,
                                queryableFieldPaths,
                                metrics,
                                referencedFacts,
                                diagnostics);
                    }
                    continue;
                }
                inspectAstNode(
                        val,
                        depth + 1,
                        profile,
                        ruleSupportsSearch,
                        ruleId,
                        pointer,
                        allFactsByPath,
                        queryableFieldPaths,
                        metrics,
                        referencedFacts,
                        diagnostics);
            }
        } else if (node instanceof List<?> list) {
            for (Object child : list) {
                inspectAstNode(
                        child,
                        depth + 1,
                        profile,
                        ruleSupportsSearch,
                        ruleId,
                        pointer,
                        allFactsByPath,
                        queryableFieldPaths,
                        metrics,
                        referencedFacts,
                        diagnostics);
            }
        }
    }

    private static final class AstMetrics {
        int maxDepth = 0;
        int nodeCount = 0;
    }
}
