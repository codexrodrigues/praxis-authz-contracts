# Actions no Fechamento de Versões

O padrão durante desenvolvimento é **zero execuções remotas**. Valide alterações localmente; commits, PRs, documentação interna e tarefas rotineiras não são motivos para iniciar workflows no GitHub Actions. Use os workflows manuais somente no fechamento autorizado de uma versão/publicação ou em validação de corte de release. Não utilize `[skip ci]` como contorno nem desabilite gates estruturais.

Antes de push, tag ou dispatch, confira os gatilhos reais em `.github/workflows/`:
- `ci.yml` (`CI`): dispara apenas por `workflow_dispatch` para validação isolada em `ubuntu-latest` (incluindo checagem da árvore de dependências runtime zero-Spring/JPA/Hibernate).
- `release.yml` (`Release Praxis Authz Contracts`): dispara por `workflow_dispatch` (job `create_tag`) ou por push de tag `v*` (job `publish`). Tags de release disparam assinatura GPG e publicação no Maven Central — **nunca crie tags `v*` para testar automação**.

## Fluxo deste repositório

1. Durante o desenvolvimento local, valide com Java 21: `mvn -B clean verify`.
2. No fechamento de versão, execute `release.yml` em `main` com `create_tag=true` (usando `RELEASE_PAT`, que persiste `pom.xml` e a tag anotada `v<semver>` atomicamente para disparar `publish`).
3. Aguarde a conclusão do probe no Maven Central (`repo1.maven.org`) antes de iniciar a publicação de `praxis-authz-enforcement-core`, `praxis-authz-opa` e `praxis-authz-starter`. Consulte [RELEASING.md](RELEASING.md).
