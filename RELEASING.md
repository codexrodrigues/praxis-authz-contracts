# Guia de Release (`praxis-authz-contracts`)

Este repositório segue a [Política de Releases e GitHub Actions](ACTIONS-RELEASE-POLICY.md) para manter releases determinísticas, auditáveis e compatíveis com os módulos dependentes da **Praxis Authorization Decision Platform**.

## Pré-requisitos do Ambiente

- **Java:** `[21, 22)` (validado pelo `maven-enforcer-plugin`)
- **Apache Maven:** `3.9.0` ou superior
- **GPG:** chave de assinatura configurada e publicada em keyserver compatível com Sonatype Central Portal (`CENTRAL_TOKEN_USER`, `CENTRAL_TOKEN_PASS`, `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`, `GPG_KEY_ID`)

## Ordem de Publicação Multi-Repositório

`praxis-authz-contracts` é a **raiz de dependência (Nível 0)** de toda a stack:

1. **`praxis-authz-contracts`** ← *(este repositório — publicar primeiro)*
2. `praxis-authz-enforcement-core` e `praxis-authz-opa` *(aguardam `praxis-authz-contracts` estar visível no Maven Central)*
3. `praxis-authz-starter` *(aguarda todos os módulos anteriores)*

## Verificação Local Pré-Release

Antes de disparar a release oficial via CI, valide localmente sem acionar deploy:

```powershell
mvn -B clean verify
```

Garanta que:
- Todos os testes de conformidade (`CC01–CC12`) e regras do `maven-enforcer-plugin` passaram;
- O `pom.xml` e os arquivos `.md` de governança estão atualizados e comworking tree limpo;
- A versão em `CHANGELOG.md` corresponde à versão alvo (ex.: `0.1.0-beta.1` ou próxima versão SemVer).

## Fluxo Oficial no GitHub Actions

Conforme [ACTIONS-RELEASE-POLICY.md](ACTIONS-RELEASE-POLICY.md):
- `ci.yml` executa **apenas** via `workflow_dispatch` (nunca em cada push de documentação ou branch comum);
- `release.yml` executa via `workflow_dispatch` (informando a versão de release e a próxima `-SNAPSHOT`, com autenticação de `RELEASE_PAT` quando aplicável) ou criação de tag `v*` pelo fluxo aprovado de release;
- O pipeline publica o bundle assinado via `central-publishing-maven-plugin` diretamente para o Sonatype Central Portal.
