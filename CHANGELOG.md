# Histórico de Alterações (Changelog)

Todas as mudanças relevantes de `praxis-authz-contracts` são documentadas neste arquivo.

O formato segue o padrão [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), e este projeto adere ao [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Adicionado
- Pacote `org.praxisplatform.authz.contracts.annotation` com anotações declarativas puras (zero dependências Spring/JPA/Hibernate/Jackson): `@AuthzTenantScope`, `@AuthzScopeAnchor`, `@AuthzCustodyPartition`, `@AuthzMask` e `@AuthzActionRule`, além de `AuthzTenantScopeMode`, `AuthzDelegationSplitMode`, `AuthzCustodyRole` e `AuthzMaskStrategy`.
- Modos e acessores neutros em `DualScopeDelegationSpec` (`ORIGIN_DESTINATION_SPLIT`, `ORIGIN_ONLY_WRITE`, `READ_ONLY_DESTINATION`, `originFactPath()`, `destinationFactPath()`, `originExclusiveWriteAttributes()`, `destinationAllowedWriteAttributes()`, `ofOriginAndDestination(...)`, `allowsDestinationWrites()` e `forbidsDestinationOnlyWrites()`), preservando os identificadores anteriores como delegados `@Deprecated` compatíveis.

## [0.1.0-beta.1] - 2026-11-15

### Adicionado
- Publicação beta inicial no Maven Central de `io.github.codexrodrigues:praxis-authz-contracts:0.1.0-beta.1` com **zero dependências de runtime**.
- Contratos canônicos do pacote `CC01–CC12`:
  - `decisionpoint`: `DecisionPointIdentity`, `DecisionPointDescriptor`, `FieldUseCategory` fechado (`VALUE`, `FILTER`, `SORT`, `GROUP`, `AGGREGATE`, `JOIN`) e `PointAuthorityMode`.
  - `context`: `FactDescriptor`, `FactContract`, `ResolvedFactValue` e resolução em 6 estados (`PRESENT`, `NULL`, `ABSENT`, `STALE`, `UNAVAILABLE`, `ERROR`).
  - `datascope`: IR `DataScopePlan` (`praxis.data-scope/v1`), `NullabilityPredicateIr`, `KleeneSearchPredicateEvaluator` e `KleeneTruthValue` em lógica Kleene de 3 valores.
  - `binding`: `RuntimeEnforcementBinding`, `EnforcementPipelineStep` (`STEP_01` a `STEP_15`) e `WriteIntent` (`SET`, `CLEAR_EXPLICIT_NULL`, `REMOVE`).
  - `policy`, `authority`, `envelope`: `AuthorizationPolicyDefinition` (`praxis.authorization-policy/v1`), `DualScopeDelegationSpec`, `EffectiveAuthorityBinding` e `ProviderEvaluationEnvelope`.
  - `masking` e `obligation`: lattice comutativo de 7 estratégias (`OMIT` > `NULLIFY` > `REDACT_CONSTANT` > `HASH_TOKEN_KEYED` > `SUMMARY_ONLY` > `CPF_CNPJ_PARTIAL` / `PARTIAL_MASK`) e barreiras *fail-closed* (`BEFORE_EXECUTION`, `BEFORE_COMMIT_OUTBOX`, `BEFORE_DISCLOSURE`).
  - `digest` e `compatibility`: `CanonicalDigestCalculator` sobre 8 estágios acíclicos (`DEFINITION_FINGERPRINT` até `BUNDLE_ARTIFACT_DIGEST`) e `HostPolicyCompatibilityManifest` (`praxis.host-policy-compatibility/v1`).
- Empacotamento reprodutível com `flatten-maven-plugin`, fontes/Javadoc assinados por GPG e regras `maven-enforcer-plugin` proibindo `org.springframework:*`, `org.springframework.boot:*`, `jakarta.persistence:*` e `org.hibernate.orm:*`.
