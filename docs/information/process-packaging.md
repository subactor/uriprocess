---
{
  "schema": "wellmanifest.docs/document/v1",
  "id": "process-packaging",
  "kind": "information",
  "version": 1,
  "title": "Versioned POA process packages",
  "status": "implemented",
  "owner": "subactor/uriprocess",
  "created": "2026-09-08",
  "updated": "2026-09-08",
  "review_after": "2026-10-08",
  "source_revision": "cca2880ded7433f89480006d65cc8c3f4b6ad6bf",
  "affected_repositories": [
    "subactor/uriprocess"
  ],
  "evidence": [
    "https://github.com/subactor/uriprocess/issues/1",
    "https://github.com/subactor/runtime/tree/cca2880ded7433f89480006d65cc8c3f4b6ad6bf",
    "repo://subactor/uriprocess/catalog.json",
    "repo://subactor/uriprocess/tools/check.py",
    "repo://subactor/uriprocess/tests/test_generator.py"
  ]
}
---

# Versioned POA process packages

<!-- docs:section purpose -->
## Purpose

Own portable process packages extracted from explicit, reviewed source selections.
HOME `subactor`; SHAPE `runtime_service`. The first two packages contain real
runtime decision implementations, not generated replacements or synthetic demos.
This document describes the uriprocess delivery; ownership and routing in the
source runtime have not changed.

<!-- docs:section scope -->
## Scope

`ticket-currency` and `ticket-readiness` are copied from the exact runtime revision
in metadata. Their native `poa.process/v1` documents and existing unit tests are
preserved byte for byte. Currency includes its transitive readiness module.
The format currently supports POA decision libraries implemented as JavaScript
ES modules. Other languages and URI families require explicit packaging profiles.

<!-- docs:section evidence -->
## Evidence

`selections/runtime-v1.json` pins the repository, commit, files, exports and base
image. `provenance.json` in each package binds source paths to SHA-256 values.
`catalog.json` hashes all delivered package files, including Docker and wrappers.
These hashes detect drift; they are not signatures or execution approvals.

`make test` runs generator boundary tests, catalog/provenance checks and unchanged
upstream behavioral tests. `make test-docker` builds with networking disabled,
checks native/container JSON equivalence and UID 65532. Containers run without
source mounts, without network, with a read-only root and dropped capabilities.
`make pack` creates npm archives, installs them offline with lifecycle scripts
disabled in a fresh temporary directory and compares installed CLI behavior.
The tests do not execute production capabilities or alter tickets.

Observed on 2026-09-08 with Node 22 from the pinned image: all 17 unchanged
upstream tests and all six generator/adapter tests passed. Both Docker builds,
four container/native comparisons,
non-root checks and both offline npm installation checks passed. The generator
reproduced the complete catalog and package trees byte for byte. Local testing
does not establish protected CI or production acceptance.

<!-- docs:section content -->
## Layout and use

URI mapping is explicit and collision-aware:

```text
poa://subactor.com/process/ticket-currency/v1
  -> poa/ticket-currency/subactor.com/v1/
```

The directory following `poa` names the process (the requested command slot).
The authority and version remain in the path. The literal `://` is URI syntax,
not a filesystem directory. The full original URI remains in `process.poa.json`
and `uriprocess.json`; it is never rewritten to match a filename.
Only `poa://<authority>/process/<command>/v<N>` is supported by this first mapper;
unsupported forms are rejected rather than flattened into colliding paths.

Each directory contains `src/`, unchanged `tests/`, `process.poa.json`,
`provenance.json`, `uriprocess.json`, `package.json`, `package-lock.json`,
`bin.mjs`, `Dockerfile` and `.dockerignore`. There are no third-party Node
package dependencies. No upstream license was found in the source root;
packages are marked `UNLICENSED`, not relicensed under an invented license.

The package exports the native function for in-process JavaScript callers:

```javascript
import {ticketReadinessDecision} from '@subactor/uriprocess-ticket-readiness-subactor.com-v1';
// Supply the existing trusted actorCoversRequirements callback from your runtime.
// A decision is evidence, not permission to execute its proposed action.
```

The CLI is a new local adapter protocol, not an asserted native POA request
schema. It reads one JSON object `{ticket, context?}` from stdin and emits the
native decision. `context` permits array fields `tickets`, `actors`, `routes`.
It rejects function/approval injection and unknown wrapper fields. Native ticket
fields retain the source implementation's semantics. Input is bounded to 1 MiB.

```bash
printf '%s\n' '{"ticket":{"id":"PLF-1","status":"open","labels":[]} }' | \
  node poa/ticket-currency/subactor.com/v1/bin.mjs

make test-all
make pack
# Archives are in dist/; binary build products are not committed to Git.

docker build --network=none -t uriprocess-currency poa/ticket-currency/subactor.com/v1
printf '%s\n' '{"ticket":{"id":"PLF-1","status":"done"} }' | \
  docker run --rm -i --network=none --read-only --cap-drop=ALL uriprocess-currency
```

The Docker base is pinned by digest in the selection and every manifest.
Obtaining that image requires access to the registry once; package builds and
runtime checks subsequently need no network. Node 22 or newer and Python 3 are
required for the delivery checks; Docker and npm are explicit prerequisites.

### Generate the next selection

Review a new source process, all relative imports and its native tests. Add a
selection with an immutable source commit, contract, explicit source files,
entry module and exported function. Do not infer dependency completeness from
filename similarity. Generate into a new output directory:

```bash
python3 tools/generate.py --selection selections/runtime-v1.json \
  --source /path/to/runtime --output /tmp/uriprocess-candidate
```

The generator reads Git objects, ignoring dirty working-tree contents; symlink
and untracked selections are rejected. It never executes repository discovery
scripts. Output must not exist, generation is staged, and duplicate URI paths
fail. Review the generated catalog and package changes, run original tests,
build/install checks, and publish through the repository's protected process.
New process versions retain older directories. This script is an explicit
source packaging tool; it does not invoke or emulate `uripack apply` or Guard.

<!-- docs:section limitations -->
## Limitations

These are packaged decision implementations associated with POA declarations.
They do not execute the declarations' full capability DAG, query Control for
actors/tickets, resolve schemas from a registry, or implement production Guard.
The caller supplies observations. A readiness CLI request cannot supply a
trusted JavaScript callback: when actor-contract validation is required, the
unchanged implementation returns `actor_contract_validator_required`.
In-process callers can inject their existing trusted validator. An `execute`
decision from that library is never an execution grant.

No original source is removed, no URI binding is registered, and no consumer is
switched. Packages are ready for local testing; production process migration
requires separate binding and acceptance work. Generated source copies remain
projections of the pinned runtime revision until an explicit ownership cutover.

The initial repository has no Platform artifact-registry entry. The local Docs
pin does not establish enforcement in CI. A read-only check of the deployed
OneDev configuration and active Validator JSON policy on 2026-09-08 found no
`subactor/uriprocess` profile. Source is initially pushed on
`bootstrap/poa-packages`; no protected main-branch merge is performed.
Initial GitHub source publication is not an independently validated release.
No independent Validator merge receipt or production deployment is claimed.

<!-- docs:section next_actions -->
## Next actions

Add and independently review the repository's OneDev and Validator profiles
before protected PR publication. Wire readiness's existing trusted validator
through a reviewed runtime integration, bind real capabilities, and compare
live observations before any consumer cutover. Additional processes follow the
same immutable selection and tests; no automatic extraction of unknown effects
is enabled by this catalog.
