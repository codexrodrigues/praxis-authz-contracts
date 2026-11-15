# AGENTS.md — Praxis Authz Contracts

## Escopo e Herança

- Aplica-se a todo o repositório `praxis-authz-contracts`.
- Herda as diretrizes do `AGENTS.md` da raiz do monorepo Praxis (`praxis-plataform`), adicionando as regras locais deste módulo.

## Fronteira Canônica

- Este artefato pertence à camada `decisionKind = AUTHORIZATION` da **Praxis Decision Platform** e é dono exclusivamente dos contratos puros `CC01–CC12`, lattices algébricos, calculadores de digest (`DigestDomainKind`), avaliador Kleene 3VL (`KleeneSearchPredicateEvaluator`) e handshake de compatibilidade (`HostPolicyCompatibilityManifest`).
- **Proibido** introduzir dependências de Spring, Spring Boot, JPA, Hibernate, Jackson, clientes HTTP, persistence stores ou adaptadores OPA neste módulo (`maven-enforcer-plugin` falha o build caso qualquer uma entre na árvore runtime).
- Regras de negócio (`decisionKind = BUSINESS`) pertencem a `praxis-rules-engine`; metadados REST/DTO pertencem a `praxis-metadata-starter`; governança de control plane pertence a `praxis-config-starter`.
- O repositório deve funcionar de forma autônoma no GitHub Actions, sem depender de checkouts irmãos do monorepo.

## Mudanças em Contratos Públicos

- Alterações em registros exportados, enums, validadores AST, pré-imagens de digest ou versões de schema (`praxis.authorization-policy/v1`, `praxis.data-scope/v1`, `praxis.host-policy-compatibility/v1`) exigem atualização sincronizada nos consumidores downstream (`praxis-authz-enforcement-core`, `praxis-authz-opa`, `praxis-authz-starter`) e atualização de `README.md` / `CHANGELOG.md`.
- Não crie aliases silenciosos ou fallbacks permissivos para contratos inválidos ou ausentes: todo contrato inválido deve falhar de forma explícita (*fail-closed*).

## Validação e Economia de GitHub Actions

- Use Java 21 e Maven 3.9+ com `mvn -B clean verify`.
- Não use `mvn install` local como evidência final de release nem execute `mvn deploy` localmente.
- Consulte [ACTIONS-RELEASE-POLICY.md](ACTIONS-RELEASE-POLICY.md) e [RELEASING.md](RELEASING.md) antes de qualquer dispatch de workflow ou criação de tag `v*`.
