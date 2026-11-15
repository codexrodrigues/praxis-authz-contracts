# Security Policy

`praxis-authz-contracts` defines the foundational contracts, canonical digest calculators, policy AST validators, masking lattices, and compatibility verifiers for the **Praxis Authorization Decision Platform**. Security-relevant defects in these contracts must be handled responsibly.

## Reporting a Vulnerability

Do **not** open public GitHub issues containing exploit payloads, sensitive host data, tokens, keys, or customer details.

Report vulnerabilities privately to the repository maintainer via GitHub Security Advisories (`codexrodrigues/praxis-authz-contracts`) and include:

- Affected version, tag, or commit hash;
- Contract class, validator, digest stage, or invariant involved (`CC01–CC12`);
- Minimal reproduction scenario without real credentials or tenant data;
- Impact assessment (e.g., digest collision, AST limit bypass, Kleene 3VL ambiguity, or mask downgrade).

## Security Design Invariants

- **Domain-Separated Acyclic Digests:** `CanonicalDigestCalculator` separates all 8 `DigestDomainKind` preimages and rejects cyclic or inverted stage dependencies (`BND-DIG-002`);
- **Bounded Candidate Policy ASTs:** `DefaultAuthorizationPolicyCandidateValidator` enforces structural limits (`MAX_AST_DEPTH`, `MAX_AST_NODES`, `MAX_IN_LITERALS`, `MAX_REFERENCED_FACTS`) and rejects disallowed operators or ungrounded fact references;
- **Fail-Closed Masking & Obligation Lattices:** Masking merges are strictly monotonic (`OMIT > NULLIFY > REDACT_CONSTANT > HASH_TOKEN_KEYED > SUMMARY_ONLY > CPF_CNPJ_PARTIAL / PARTIAL_MASK`), and incompatible obligation triggers or barriers fail with explicit conflicts;
- **3-Valued Null Safety:** `KleeneSearchPredicateEvaluator` preserves `UNKNOWN` for missing/absent facts so neither `IS_NULL` nor `NOT(IS_NULL)` silently widens access.

## Credential & Release Hygiene

- Never commit Maven Central tokens, GitHub PATs, GPG private keys, passphrases, or HMAC secrets;
- All Maven Central releases require GPG signatures generated exclusively in CI via GitHub Secrets (see [RELEASING.md](RELEASING.md)).
