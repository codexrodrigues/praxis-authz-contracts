# Changelog

All notable changes to `praxis-authz-contracts` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-beta.1] - 2026-11-15

### Added
- Initial Maven Central beta publication of `io.github.codexrodrigues:praxis-authz-contracts:0.1.0-beta.1`.
- Complete Contract Closure Pack (`CC01–CC12`) in pure Java 21 with zero transitive runtime dependencies:
  - `decisionpoint`: `DecisionPointIdentity`, `DecisionPointDescriptor`, `FieldUseCategory` (closed 6-category vocabulary), and `PointAuthorityMode`;
  - `context`: `FactDescriptor`, `FactContract`, `ContextCompositionProfile`, 6-state `ResolvedFactValue`, `ProviderInputProjection`, and `TemporalContext`;
  - `datascope`: `DataScopePlan` (`praxis.data-scope/v1`), `QueryableResourceProjection`, `SearchPredicateIr`, and `KleeneSearchPredicateEvaluator`;
  - `binding`: `RuntimeEnforcementBinding`, 15-step `EnforcementPipelineStep`, and `WriteIntent` (`SET`, `CLEAR_EXPLICIT_NULL`, `REMOVE`);
  - `policy`: `AuthorizationPolicyDefinition` (`praxis.authorization-policy/v1`), `DefaultAuthorizationPolicyCandidateValidator`, and `DualScopeDelegationSpec`;
  - `authority` & `envelope`: `EffectiveAuthorityBinding`, `ProviderEvaluationEnvelope`, and `DecisionEvidence`;
  - `masking`: `MaskStrategyRegistry` and `DefaultMaskStrategyRegistry` implementing the 7-strategy commutative merge lattice;
  - `obligation`: `ObligationHandlerRegistry` and `DefaultObligationHandlerRegistry` (`REQUIRE_MFA`, `REQUIRE_JUSTIFICATION`, `DURABLE_AUDIT_EVIDENCE`, `WATERMARK`);
  - `digest`: 8-stage acyclic `DigestDomainKind` DAG, `CanonicalDigestCalculator`, `OpaRuntimeRelease`, and `OpaRuntimeHead`;
  - `compatibility`: `HostPolicyCompatibilityManifest`, `ImpactGraphBaseline`, and `DefaultHostPolicyCompatibilityVerifier`.
- Reproducible Maven release pipeline with `flatten-maven-plugin`, source/Javadoc packaging, GPG signing, and Maven Enforcer rules banning Spring, Hibernate, and JPA dependencies.
