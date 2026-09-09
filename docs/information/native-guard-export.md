---
{
  "schema": "wellmanifest.docs/document/v1",
  "id": "native-guard-export",
  "kind": "information",
  "version": 1,
  "title": "Native Guard plan, export and verified package retrieval",
  "status": "implemented",
  "owner": "subactor/uriprocess",
  "created": "2026-09-08",
  "updated": "2026-09-08",
  "review_after": "2026-10-08",
  "source_revision": "9d314b4b9ec735eb90bab136393deaf124e38879",
  "affected_repositories": [
    "subactor/uriprocess"
  ],
  "evidence": [
    "https://github.com/subactor/uriprocess/issues/4",
    "https://github.com/subactor/organism-guard/issues/2",
    "repo://subactor/uriprocess/tools/guard_export.py",
    "repo://subactor/uriprocess/integration_tests/full_guard_export.py",
    "repo://subactor/uriprocess/integration/organism-guard-export.json"
  ]
}
---

# Native Guard export and verified retrieval

<!-- docs:section purpose -->
## Purpose

Extend the existing read-only observation integration into an actual native
plan, separate admission, executor operation and verified artifact retrieval.
The existing `ticket-currency` and `ticket-readiness` implementations retain
their source bytes, original POA contracts and authority namespace directories.

<!-- docs:section scope -->
## Scope

The new Guard 0.10.0 backend owns `fastlane-unit-export`, using the existing
Fastlane exporter, native plan/grant store and recovery. Its source commit,
contract digest and Python source-tree digest are pinned in
`integration/organism-guard-export.json`. The consumer delegates to GuardClient;
it contains no author approval command, new authority database or provider
client. Safe local writes and atomic no-replace publication reuse the pinned
uripack executor's existing helpers rather than duplicating those primitives.
This is an explicit integration with those private helpers at the recorded
revision, not an assertion that they are a stable public SDK.

<!-- docs:section evidence -->
## Evidence

`integration_tests/full_guard_export.py` starts the real native HTTP service
with separate, explicitly test-only author, reviewer and executor identities.
It verifies the installed Guard source tree, contract digest and uripack
executor file digest against the compatibility reference before testing.
It copies immutable uriprocess commit
`f76773988ccdccd81725ce93017c66615b84a8fb` into a temporary test repository,
adds the explicit test policy and commits that test base. The original checkout
is neither modified nor treated as independently approved policy.

Observed locally on 2026-09-08: both real process packages traversed CLI planning,
independent test-role admission, CLI execution, native receipt/artifact readback,
local materialization, all 17 original upstream tests, Docker build/run and
an offline npm installation in a separate directory. Downloaded behavior matched
the source implementation, including Unicode input. A repeated fetch reads
evidence and does not execute the export again. Negative checks reject planner
execution, existing destinations and corrupted bundle content. Native Guard's
494-test suite, including missing grants, self-approval, stale plans and
crash/readback recovery, passed in its owning repository.

This proves a full local reference flow, not independent production approval.
Test credentials are ephemeral. No production Guard, secret access, source
removal, consumer cutover, registry publication or protected merge was executed.
The emitted report records this distinction and the exact temporary test base.

<!-- docs:section content -->
## Client commands

Install independently reviewed, pinned Guard and uripack releases outside the
candidate. The two libraries must be available to the selected Python runtime.
No command auto-installs a package or silently substitutes a test server.
The operator supplies the endpoint, scoped bearer in an environment variable,
registered repository ID, exact source revision, unit and contract digest.

`tools/guard_export.py` has three actions:

| Action | Input | Effect |
| --- | --- | --- |
| `plan` | ticket, repository, immutable revision, unit | Store typed input and obtain a native plan; no export or approval. |
| `execute` | independently issued native execution envelope and the same source scope | Execute through Guard, fetch a verified receipt and artifact, then materialize locally. |
| `fetch` | plan ID, exact plan hash and source scope | Retrieve completed evidence and materialize without replaying execution. |

All commands take `--base-url`, `--contract-sha256`, `--repository-id`,
`--revision`, `--unit` and `--out`. The author uses `--ticket-id` with `plan`.
The executor uses `--envelope` and a new `--target` with `execute`.
Readback uses `--plan-id`, `--plan-sha256` and a new `--target` with `fetch`.
The default token variable is `URIPROCESS_GUARD_TOKEN`; each independent actor
supplies its own token, or explicitly names its own variable with `--token-env`.
Never put a bearer in argv, a URL, ticket, output JSON or repository file.

There is deliberately no client `approve` action. The operator's independent
approver uses native `admission.decide` against the returned exact plan/hash/
queue revision and gives the executor its native envelope. The server binds
it to the configured executor and rechecks source/policy currency. A stale
plan must be planned and reviewed again; changing JSON does not renew it.

Before local materialization the consumer independently retrieves `plan.get`,
`receipt.get` and `artifact.get`, validates their native hashes and cross-bindings,
and verifies every path, byte hash and mode. Results go to a new directory;
existing targets, including empty directories, are not overwritten. Raw error
bodies are withheld. Failed or uncertain server execution is not retried.
If a local receipt-file write fails after an export, use native receipt readback
and a new fetch target; do not infer that no server effect occurred.

### Export policy proposal

`integration/fastlane-project.proposed.json` explicitly names both package units.
It is a reviewable authoring proposal, not installed authority. Implementation
files are writable only within their own unit. Package descriptors, contracts,
provenance, Docker inputs and original tests remain read-only context, explicitly
included via the new `export_paths` field. This field grants export access, not
permission to modify those files. Guard enforces that it is a subset of the
approved read/write set and retains the complete unit implementation.

Paths retain `poa/command/subactor.com/v1/`; local Guard ownership IDs also name
`subactor.com`. A later `default` profile must have separate ownership IDs,
contracts, provenance and conformance tests. It never silently replaces an
original namespace. No production capability URI is inferred from these local
Guard ownership IDs.

### Prepared operator deployment

`operator/guard-server.proposed.json` supplies the native closed configuration
with separate author/approver/executor token environment names. It has no secret
values and keeps candidate test execution disabled. `operator/uriprocess-guard.service`
is a proposed systemd unit with a dedicated account, read-only repository
mount policy and writable server state outside the checkout. Neither file is
installed or enabled by this delivery.

Before deployment the independent operator must:

1. Review/publish the Guard extension and consumer through the required CI and
   independent Validator, then install their exact releases under the protected
   paths named by the service unit.
2. Independently approve the source manifest as `.guard/fastlane.json` on a
   protected source `main`. The current bootstrap branch is not silently renamed
   or promoted into an approved main by this tool.
3. Provision the dedicated account and isolated control-state storage. Place the
   native server config outside candidates; keep server credentials readable only
   by its operator/service and distribute individual scoped tokens to the
   separate actors. Register the real current ticket and repository path.
4. Review the proposed systemd restrictions for that installation and start the
   native loopback service. Remote use needs the existing authenticated TLS
   boundary; do not expose plaintext bearer HTTP externally.
5. Reobserve the installed contract and exact source revision, execute a bounded
   approved export and verify the returned package with independent acceptance.

These are deployment prerequisites, not completed deployment claims. There is
no observed protected Guard configuration or deployed CI/Validator profile for
uriprocess in the current session. Never manufacture an approval to fill that gap.

### Reproduce the local reference flow

With the exact pinned native packages installed and Node 22, npm and Docker:

```bash
make test-guard-export \
  GUARD_SOURCE=/path/to/uriprocess \
  GUARD_REVISION=f76773988ccdccd81725ce93017c66615b84a8fb \
  GUARD_OUTPUT=/private/evidence/new-full-export
```

The output directory must not exist. The test leaves both materialized packages,
npm archives and its report there; private server/test-repository state and
credentials are removed. Docker containers run without source mounts or network,
with a read-only root and dropped capabilities. `make test` retains the ordinary
11 Python and 17 unchanged upstream tests; native integrations are explicit
additional targets and never silently skipped when their dependencies are absent.

<!-- docs:section limitations -->
## Limitations

Native export verifies source fidelity; it does not execute the POA capability
DAG, prove semantic architecture, bind production URI consumers or deploy a
service. The reference server is not an OS sandbox. Its server state, SDK,
policy and credentials must be protected independently of candidates.
Checksums detect drift but do not attest a remote server binary or constitute
cryptographically signed third-party approval. The authenticated configured
endpoint remains the client trust boundary.

The backend limits source to 64 KiB and canonical results to 120,000 bytes.
Larger bundles require an explicit reviewed transport profile; no truncation or
unbounded HTTP fallback is provided. No automatic Strategy scheduler is added:
the client invokes the registered native process under an explicit operator
workflow. Rollout to a protected runtime and its independent acceptance remain
separate from the passing local reference tests.

<!-- docs:section next_actions -->
## Next actions

Complete independent publication and operator provisioning, then run the same
bounded two-package acceptance against that protected endpoint with genuinely
separate credentials. Only after that evidence should production source/URI
ownership migration or additional standard adapters be enabled.
