# Praxis Authz Contracts

Framework-neutral contracts, algebraic lattices, digest calculators, and SPIs for the Praxis Authorization Decision Platform.

## Highlights

- **Decision Point & Fact Contracts:** `DecisionPointDescriptor`, `FactContract`, `FactDescriptor`, `RuntimeEnforcementBinding`, and `ContextCompositionProfile`.
- **Persistence-Neutral Data Scope IR:** `DataScopePlan`, `QueryableResourceProjection`, `SearchPredicateIr`, and `KleeneSearchPredicateEvaluator` preserving Kleene 3-valued logic.
- **Policy AST & Canonical Digests:** `AuthorizationPolicyDefinition` and RFC 8785 JCS `CanonicalDigestCalculator` across 8 acyclic digest domains.
- **Startup Handshake Contracts:** `HostPolicyCompatibilityManifest` and `DefaultHostPolicyCompatibilityVerifier`.
- **Zero Framework Lock-In:** Pure Java 21 contracts with no Spring Boot or Hibernate ORM dependencies.

## Maven Coordinates

```xml
<dependency>
    <groupId>io.github.codexrodrigues</groupId>
    <artifactId>praxis-authz-contracts</artifactId>
    <version>0.1.0-beta.1</version>
</dependency>
```

## License

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
