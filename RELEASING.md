# Releasing — Praxis Authz Contracts

## Public line

The active public line is `0.1.0-beta.*` under coordinate `io.github.codexrodrigues:praxis-authz-contracts` (current published release: `0.1.0-beta.1`). Compatible corrections remain on this line while downstream modules and hosts validate the contract. A stable `1.0.0` or new major requires a governed compatibility and migration plan.

## Multi-repository release order

Because downstream modules bind `<praxis-authz.version>${project.version}</praxis-authz.version>` and `release.yml` verifies upstream `.pom` files on `repo1.maven.org` before tagging, coordinate releases across the four repositories strictly in dependency order:

1. `codexrodrigues/praxis-authz-contracts` (this repository; no upstream `praxis-authz-*` dependencies)
2. `codexrodrigues/praxis-authz-enforcement-core` (verifies `praxis-authz-contracts:<version>` `HTTP 200` on Maven Central)
3. `codexrodrigues/praxis-authz-opa` (verifies `praxis-authz-contracts` and `praxis-authz-enforcement-core` on Maven Central)
4. `codexrodrigues/praxis-authz-starter` (verifies `praxis-authz-contracts`, `praxis-authz-enforcement-core`, and `praxis-authz-opa` on Maven Central)

All four modules in a coordinated wave must publish the exact same SemVer version string.

## Required repository secrets

- `CENTRAL_TOKEN_USER`
- `CENTRAL_TOKEN_PASS`
- `GPG_PRIVATE_KEY` (ASCII-armored private key block with the mandatory RFC 4880 blank line immediately after `-----BEGIN PGP PRIVATE KEY BLOCK-----`, or base64-encoded binary key export)
- `GPG_PASSPHRASE`
- `GPG_KEY_ID` (optional)
- `RELEASE_PAT`, with `contents: write` permission to push commits and tags on `main`

`RELEASE_PAT` is required because tags pushed by `GITHUB_TOKEN` do not trigger the separate `push: tags: v*` publication workflow.

## Release flow

1. Confirm the intended commit is on remote `main`, the working tree is clean, and local validation passes with JDK 21:

   ```powershell
   mvn -B clean verify
   ```

2. In GitHub Actions, run **Release Praxis Authz Contracts** (`workflow_dispatch`) on `main` with `create_tag=true` and either an explicit `version` or `bump`/`preid`.
3. The `create_tag` job verifies release readiness, persists the resolved version in `pom.xml`, creates the annotated `v<semver>` tag, and pushes `HEAD:main` and the tag atomically.
4. The `publish` job verifies tag ancestry on `main`, imports the GPG key, enforces module boundaries (`maven-enforcer-plugin`), runs tests, flattens the published POM (`flatten-maven-plugin`, `oss` mode), signs `.pom`/`.jar`/`-sources.jar`/`-javadoc.jar`, publishes via `central-publishing-maven-plugin`, and polls `repo1.maven.org` until the `.pom` returns `HTTP 200`.
5. Only start `praxis-authz-enforcement-core` after the Maven Central availability probe in this workflow succeeds.
6. Keep note of the `pom.xml` version on `main`: `create_tag` commits the released version (`0.1.0-beta.x`) in `pom.xml`, and `release.yml` computes future releases from `v*` git tags. Before running `mvn install` locally for new unreleased work, bump `<version>` to the next `-SNAPSHOT` (e.g. `0.1.0-beta.2-SNAPSHOT`) so local builds do not overwrite published release artifacts in `~/.m2`.
7. Validate published coordinates with an isolated empty local repository (`mvn -B -Dmaven.repo.local=<temp-dir> dependency:tree`) against `repo1.maven.org`; a local Maven install is not release evidence.

Do not create release tags manually, run `mvn deploy` locally, or bypass a failed CI/release gate.
