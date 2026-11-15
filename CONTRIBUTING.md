# Contributing to Praxis Authz Contracts

Thank you for contributing to `praxis-authz-contracts`.

## Development Baseline

- **Java:** 21 (`[21,22)` enforced by `maven-enforcer-plugin`)
- **Maven:** 3.9.0 or newer

Run full local verification before submitting changes:

```powershell
mvn -B clean verify
```

Verify that the runtime dependency tree remains empty (`0` transitive dependencies):

```powershell
mvn -B dependency:tree -Dscope=runtime
```

## Module Boundary & Enforcer Rules

`praxis-authz-contracts` is the pure contract foundation of the **Praxis Authorization Decision Platform**:

- Keep all contracts framework-neutral. **Never** add dependencies on `org.springframework.*`, `org.springframework.boot.*`, `jakarta.persistence.*`, `org.hibernate.orm.*`, Jackson, HTTP clients, or OPA SDKs;
- Keep business rule semantics (`decisionKind = BUSINESS`) in `praxis-rules-engine` and control-plane persistence/authoring in `praxis-config-starter`;
- Keep resource/UI metadata semantics (`@ApiResource`, `x-ui`, `/schemas/**`) in `praxis-metadata-starter`.

## Contract & Release Discipline

- Changes to exported records, enums, SPI interfaces, digest preimages, or schema versions (`praxis.authorization-policy/v1`, `praxis.data-scope/v1`, `praxis.host-policy-compatibility/v1`) affect downstream modules (`praxis-authz-enforcement-core`, `praxis-authz-opa`, `praxis-authz-starter`) and must be validated across the chain;
- Update Javadoc, `README.md`, and `CHANGELOG.md` whenever public contracts change;
- Never commit secrets, GPG material, personal tokens, or environment-specific URLs;
- Do not create release tags manually or run local `mvn deploy`; follow [RELEASING.md](RELEASING.md).
