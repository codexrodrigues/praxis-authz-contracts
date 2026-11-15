# Como Contribuir com `praxis-authz-contracts`

Contribuições para `praxis-authz-contracts` devem preservar a neutralidade de framework, o determinismo criptográfico e a compatibilidade com os demais projetos da **Praxis Platform**.

## Baseline de Desenvolvimento

- **Java:** 21 (`[21,22)` imposto pelo `maven-enforcer-plugin`)
- **Apache Maven:** `3.9.0` ou superior

Execute a verificação completa localmente antes de enviar alterações:

```powershell
mvn -B clean verify
```

Confirme explicitamente que a árvore de dependências de runtime permanece vazia (`0` dependências transitivas):

```powershell
mvn -B dependency:tree -Dscope=runtime
```

## Fronteira de Módulo e Regras do Enforcer (`BND-OWN-001`)

`praxis-authz-contracts` é a fundação de contratos puros da **Praxis Authorization Decision Platform**:

1. **Zero Dependências de Framework:** **Nunca** adicione dependências de `org.springframework:*`, `org.springframework.boot:*`, `jakarta.persistence:*`, `org.hibernate.orm:*`, Jackson, clientes HTTP ou SDKs OPA neste módulo. Adaptações Spring/JPA pertencem a [`praxis-authz-enforcement-core`](https://github.com/codexrodrigues/praxis-authz-enforcement-core) ou [`praxis-authz-starter`](https://github.com/codexrodrigues/praxis-authz-starter).
2. **Separação de Planos:** Mantenha a semântica de regras de negócio (`decisionKind = BUSINESS`) em [`praxis-rules-engine`](https://github.com/codexrodrigues/praxis-rules-engine), persistência/autoria de control plane em [`praxis-config-starter`](https://github.com/codexrodrigues/praxis-config-starter) e metadados REST/UI (`@ApiResource`, `x-ui`, `/schemas/**`) em [`praxis-metadata-starter`](https://github.com/codexrodrigues/praxis-metadata-starter).
3. **Semântica Cross-Canal e Imutabilidade:** Prefira `record`s, `enum`s selados e validadores estritos em vez de mapas soltos `Map<String, Object>`, garantindo operação uniforme em UI tradicional, UI generativa, agentes de IA e sidecars OPA.
4. **Cobertura de Conformidade (`CC01–CC12`):** Novos campos, nós de `DataScopePlan` ou estágios em `PolicyDigestChain` exigem testes determinísticos cobrindo serialização canônica e casos extremos (especialmente `UNKNOWN` em lógica Kleene 3VL).

## Disciplina de Contratos, Documentação e Release

- Alterações em registros exportados, enums, interfaces SPI, pré-imagens de digest ou versões de schema (`praxis.authorization-policy/v1`, `praxis.data-scope/v1`, `praxis.host-policy-compatibility/v1`) impactam toda a cadeia downstream (`praxis-authz-enforcement-core`, `praxis-authz-opa`, `praxis-authz-starter`) e devem ser validadas de ponta a ponta;
- Atualize JavaDocs, `README.md` e `CHANGELOG.md` em **PT-BR** claro e didático (preservando os identificadores exatos da API) sempre que contratos públicos mudarem;
- Nunca comite segredos, chaves GPG, tokens pessoais ou URLs específicas de ambiente;
- Não crie tags manuais nem execute `mvn deploy` localmente; siga [RELEASING.md](RELEASING.md), [AGENTS.md](AGENTS.md) e [ACTIONS-RELEASE-POLICY.md](ACTIONS-RELEASE-POLICY.md).
