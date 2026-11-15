# Política de Segurança (`praxis-authz-contracts`)

`praxis-authz-contracts` define os contratos canônicos de identidade, fatos em 6 estados, escopo relacional Kleene 3VL, lattice comutativo de mascaramento, barreiras de obrigações e cadeia acíclica de 8 estágios de digest da **Praxis Authorization Decision Platform**. Defeitos com impacto de segurança devem ser comunicados de forma responsável e confidencial.

## Reportando uma Vulnerabilidade

**Não** abra issues públicas no GitHub contendo payloads de exploração, detalhes de vulnerabilidades em produção, credenciais, tokens, chaves privadas ou dados de clientes.

Envie o relato em canal privado ao mantenedor via **GitHub Security Advisories** (`codexrodrigues/praxis-authz-contracts`), informando:

- Versão, tag ou hash de commit afetado;
- Contrato ou pacote envolvido (por exemplo: `KleeneSearchPredicateEvaluator`, `CanonicalDigestCalculator`, `ResolvedFactValue`, `DefaultMaskStrategyRegistry`, `DefaultAuthorizationPolicyCandidateValidator` ou `DefaultHostPolicyCompatibilityVerifier`);
- Cenário mínimo reproduzível sem dados sensíveis ou reais;
- Impacto de segurança observado (por exemplo: colisão ou desvio na cadeia de 8 digests, contorno de lógica Kleene 3VL com `ABSENT`/`NULL`, ou quebra de dominância no lattice de mascaramento).

## Invariantes de Segurança por Design

- **Verdade Estrita em Kleene 3VL:** A avaliação de `DataScopePlan` distingue explicitamente `TRUE`, `FALSE` e `UNKNOWN` (ex.: `IS_NULL(ABSENT) = UNKNOWN`, `NOT(UNKNOWN) = UNKNOWN`), exigindo estritamente `TRUE` para concessão;
- **Fatos em 6 Estados:** `FactResolutionStatus` impede que `ABSENT`, `STALE`, `UNAVAILABLE` ou `ERROR` sejam tratados como valores válidos ou booleanos falsos;
- **Dominância em Lattice Comutativo:** No mascaramento, `OMIT` (100) prevalece sobre qualquer estratégia inferior em `DefaultMaskStrategyRegistry`;
- **Integridade Acíclica em 8 Domínios (`DigestDomainKind`):** Alterações estruturais da definição até o artefato compilado invalidam automaticamente o handshake `praxis.host-policy-compatibility/v1`.

## Higiene de Credenciais e Releases

- Nunca versione tokens do Sonatype Central Portal, PATs do GitHub ou chaves GPG neste repositório;
- Toda publicação oficial ocorre apenas pelo fluxo automatizado e assinado descrito em [RELEASING.md](RELEASING.md).
