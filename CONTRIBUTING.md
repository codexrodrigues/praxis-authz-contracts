# Como Contribuir com `praxis-authz-contracts`

Contribuições para `praxis-authz-contracts` devem preservar a neutralidade de framework, o determinismo criptográfico e a compatibilidade com os demais projetos da **Praxis Platform**.

## Princípios de Contribuição

1. **Zero Dependências de Framework (`BND-OWN-001`):** Nunca adicione `org.springframework:*`, `org.springframework.boot:*`, `jakarta.persistence:*`, `org.hibernate.orm:*` ou clientes HTTP neste módulo. Se um contrato precisar de integração JPA ou Spring, o lugar correto é [`praxis-authz-enforcement-core`](https://github.com/codexrodrigues/praxis-authz-enforcement-core) ou [`praxis-authz-starter`](https://github.com/codexrodrigues/praxis-authz-starter).
2. **Contratos Imutáveis e Tipados:** Prefira `record`s, `enum`s fechados e contratos auto-validáveis em vez de mapas soltos `Map<String, Object>`.
3. **Semântica Cross-Canal:** Toda mudança de contrato deve considerar seu impacto simultâneo em interfaces tradicionais, interfaces generativas, agentes de IA e sidecars OPA — nunca introduza atalhos específicos de um único consumidor.
4. **Cobertura de Conformidade (`CC01–CC12`):** Novos campos, nós de `DataScopePlan` ou estágios em `PolicyDigestChain` exigem testes determinísticos cobrindo serialização canônica e casos extremos (especialmente `UNKNOWN` em lógica Kleene 3VL).
5. **Documentação em PT-BR e Inglês Técnico Consistente:** Documente APIs públicas, JavaDocs e atualizações de guia em Português do Brasil claro e didático, mantendo os identificadores técnicos exatos do código.

## Fluxo de Trabalho Local

```powershell
mvn -B clean verify
```

- Consulte [AGENTS.md](AGENTS.md) para convenções de engenharia aplicadas a humanos e agentes;
- Consulte [ACTIONS-RELEASE-POLICY.md](ACTIONS-RELEASE-POLICY.md) antes de propor mudanças em `.github/workflows/`.
