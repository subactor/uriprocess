---
{
  "schema": "wellmanifest.docs/document/v1",
  "id": "guard-observation",
  "kind": "information",
  "version": 1,
  "title": "Native Organism Guard observation during refactoring",
  "status": "implemented",
  "owner": "subactor/uriprocess",
  "created": "2026-09-08",
  "updated": "2026-09-08",
  "review_after": "2026-10-08",
  "source_revision": "f76773988ccdccd81725ce93017c66615b84a8fb",
  "affected_repositories": [
    "subactor/uriprocess"
  ],
  "evidence": [
    "https://github.com/subactor/uriprocess/issues/2",
    "repo://subactor/uriprocess/tools/guard_observe.py",
    "repo://subactor/uriprocess/integration/organism-guard.json",
    "repo://subactor/uriprocess/integration_tests/guard_http.py"
  ]
}
---

# Native Organism Guard observation

<!-- docs:section purpose -->
## Purpose

Use the existing Organism Guard boundary to observe the repository revision
before refactoring. This is a read-only integration, not repository admission
or a second implementation of Guard policy. Earlier process extraction did not
use Guard; this change adds actual native API use with a bounded role.

<!-- docs:section scope -->
## Scope

The consumer calls `GuardClient` from a separately installed operator-selected
`organism_guard` package. HTTP dispatch stays in native `GuardService.call`.
Only `system.discover` and `git.status` are used. There is no provider client,
local Git fallback, automatic server launch, approval, lease, ref update or
production routing in `tools/guard_observe.py`.

<!-- docs:section evidence -->
## Evidence

The compatibility reference is Organism Guard 0.9.0 at Git commit
`c982569141cd85a799b5f6ddb6cc423a56e23470`. The exact native contract digest and
Python source-tree digest are in `integration/organism-guard.json`.
The integration runner verifies the installed Python source tree before starting
the real native loopback HTTP server. During this delivery those sources were
exported from immutable Git objects into a private directory; the existing
Guard working tree and its unrelated changes were preserved.

Observed locally on 2026-09-08: the real HTTP service observed the initial
uriprocess commit `f76773988ccdccd81725ce93017c66615b84a8fb`. Eight integration
checks cover exact-head observation, real CLI output, overwrite refusal, wrong
contract pin, stale head, invalid bearer, reader admission denial and a dirty
temporary Git repository. These
are actual HTTP/Git operations, not a RuntimePort or server double. Unit tests
use an explicitly named client double to test malformed and changing replies.
Neither set proves production Guard deployment or architecture conformance.

<!-- docs:section content -->
## Configuration and use

The operator supplies the installed SDK, authenticated endpoint, scoped reader
token, registered repository ID and independently expected contract/head pins.
Do not derive the expected contract digest from the same discovery response
being checked. The compatibility JSON is a reviewable reference; it is not a
production trust store or execution grant.

```bash
python3 tools/guard_observe.py \
  --base-url http://127.0.0.1:8765 \
  --repository-id uriprocess \
  --expected-head f76773988ccdccd81725ce93017c66615b84a8fb \
  --expected-contract-sha256 5bde88196983bc51fafa37af37742e68f13c0af136125004aaeb0ceeaf03a117 \
  --out /private/evidence/uriprocess-observation.json
```

This command expects an already configured server. The URL and output path are
operator examples, not observed production endpoints. A bearer must already be
present in `URIPROCESS_GUARD_TOKEN` (or the explicitly named `--token-env`).
No token appears in argv, URLs or the result. Native client behavior rejects
redirects and non-loopback plaintext HTTP. Transport error details are suppressed.
Missing credentials, SDK, stale/dirty state and contract drift fail without a
success file. Existing output files are never overwritten.

The report contains only the expected revision, contract digest, Guard version,
observation time and bounded scope. Raw porcelain paths and credentials are not
copied. Both status reads must observe a clean repository at the exact head.
The report explicitly sets `execution_authority`, `publication_authorized` and
`architecture_verified` to false.

Run client/unit and unchanged source behavior tests with `make test`.
Run the separate real native integration with a clean registered Git checkout:

```bash
make test-guard GUARD_REPOSITORY=/path/to/clean/uriprocess \
  GUARD_REPORT=/private/evidence/new-guard-test.json
```

The pinned native SDK/API dependencies must already be installed. The test
creates fresh local credentials and state outside the repository and binds to
loopback. Its reader cannot approve. The required native executor identity has
no repository scope or bearer credential, and local execution opt-in is false.
The server and its private temporary state are removed after testing. It is
never installed as a production authorization service.

### URI namespaces

Retain `poa/ticket-currency/subactor.com/v1/` and corresponding readiness paths.
The authority namespace allows future adapters or standards to coexist. A future
`default` namespace must have its own explicit contract, provenance and tests;
there is no silent fallback or inferred equivalence with the original standard.
No default implementation is generated by this change.

<!-- docs:section limitations -->
## Limitations

Two observations are not a lock: they cannot prevent a later change or detect
all change-and-revert activity between requests. Reports are point-in-time,
unsigned evidence, not trusted merge receipts. A contract hash checks interface
compatibility; it does not attest a remote server binary. The local integration
runner's source digest check applies only to that test installation.

The native classic architecture scanner requires operator-authored workspace
and component manifests, and its Python analysis does not establish semantic
coverage for these JavaScript packages. No normative policy is generated from
the candidate code. The uripack protected apply bridge is still a separate
contract, with no verified production adapter to this Guard API.

No admission, execution, architecture scan, capability registration, full POA
DAG execution, production Guard connection or protected merge is claimed.
The current generator remains an explicit offline source packager; this
observation tool does not convert its output into an approved migration.
The repository's independent OneDev/Validator profiles remain missing.

<!-- docs:section next_actions -->
## Next actions

Before using Guard for mutation, independently define and review ownership,
write scopes, native capability bindings and the bridge to the existing
publication boundary. Keep one authority per resource and preserve source
namespaces. After profile deployment, obtain exact-head protected CI and an
independent Validator decision for the material PR; observe production
acceptance separately before switching consumers.
