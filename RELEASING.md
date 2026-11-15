# Guia de Release — Praxis Authz Contracts

## Linha Pública

A linha pública ativa é `0.1.0-beta.*` sob a coordenada `io.github.codexrodrigues:praxis-authz-contracts` (release atual publicada: `0.1.0-beta.1`). Correções compatíveis seguem nesta linha enquanto módulos downstream e hosts validam o contrato. Uma versão estável `1.0.0` ou nova *major* exige plano governado de compatibilidade e migração.

Este repositório segue a [Política de Releases e GitHub Actions](ACTIONS-RELEASE-POLICY.md).

## Ordem Sequencial de Publicação Multi-Repositório (4 Etapas)

Como os módulos downstream vinculam `<praxis-authz.version>${project.version}</praxis-authz.version>` e o `release.yml` verifica os arquivos `.pom` upstream no `repo1.maven.org` antes de criar a tag, coordene as releases dos quatro repositórios **estritamente em ordem sequencial de dependência**:

1. **`codexrodrigues/praxis-authz-contracts`** *(este repositório — publicar primeiro; não possui dependências upstream `praxis-authz-*`)*
2. `codexrodrigues/praxis-authz-enforcement-core` *(valida `praxis-authz-contracts:<versão>` com `HTTP 200` no Maven Central antes da tag)*
3. `codexrodrigues/praxis-authz-opa` *(valida `praxis-authz-contracts` e `praxis-authz-enforcement-core` com `HTTP 200` no Maven Central antes da tag)*
4. `codexrodrigues/praxis-authz-starter` *(valida `praxis-authz-contracts`, `praxis-authz-enforcement-core` e `praxis-authz-opa` com `HTTP 200` no Maven Central antes da tag)*

Todos os quatro módulos de uma onda coordenada devem publicar exatamente a mesma string de versão SemVer.

## Segredos Obrigatórios no Repositório

- `CENTRAL_TOKEN_USER`
- `CENTRAL_TOKEN_PASS`
- `GPG_PRIVATE_KEY` (bloco ASCII-armored com a linha em branco obrigatória pela RFC 4880 imediatamente após `-----BEGIN PGP PRIVATE KEY BLOCK-----`, ou exportação binária codificada em base64)
- `GPG_PASSPHRASE`
- `GPG_KEY_ID` (opcional)
- `RELEASE_PAT`, com permissão `contents: write` para enviar commits e tags para `main`

`RELEASE_PAT` é obrigatório porque tags enviadas via `GITHUB_TOKEN` não disparam o workflow separado com gatilho `push: tags: v*`.

## Fluxo Oficial de Release

1. Confirme que o commit alvo está em `main` remoto, o working tree está limpo e a validação local passa com JDK 21 (`[21,22)`) e Maven `3.9.0+`:

   ```powershell
   mvn -B clean verify
   ```

2. No GitHub Actions, execute **Release Praxis Authz Contracts** (`workflow_dispatch`) em `main` com `create_tag=true` e informe explicitamente `version` ou `bump`/`preid`.
3. O job `create_tag` valida a prontidão da release, persiste a versão resolvida no `pom.xml`, cria a tag anotada `v<semver>` e envia `HEAD:main` e a tag atomicamente.
4. O job `publish` verifica a ancestralidade da tag em `main`, importa a chave GPG, impõe fronteiras de módulo (`maven-enforcer-plugin`), executa os testes (`CC01–CC12`), gera o POM achatado (`flatten-maven-plugin`, modo `oss`), assina `.pom`/`.jar`/`-sources.jar`/`-javadoc.jar`, publica via `central-publishing-maven-plugin` e consulta `repo1.maven.org` até o `.pom` retornar `HTTP 200`.
5. Somente inicie a release de `praxis-authz-enforcement-core` após o probe de disponibilidade no Maven Central deste workflow concluir com sucesso.
6. Atenção à versão no `pom.xml` em `main`: `create_tag` grava a versão publicada (`0.1.0-beta.x`) no `pom.xml`, e o `release.yml` calcula releases futuras a partir das tags git `v*`. Antes de rodar `mvn install` localmente para desenvolvimento inédito ainda não publicado, avance `<version>` para o próximo `-SNAPSHOT` (ex.: `0.1.0-beta.2-SNAPSHOT`) para que builds locais não sobrescrevam artefatos de release publicados em `~/.m2`.
7. Valide as coordenadas publicadas usando um repositório local temporário isolado e vazio contra `repo1.maven.org`; um `mvn install` local nunca substitui a evidência oficial de release:

   ```powershell
   mvn -B -Dmaven.repo.local=<temp-dir> dependency:tree
   ```

Nunca crie tags de release manualmente para disparar CI, não execute `mvn deploy` localmente nem contorne gates de CI/release reprovados.
