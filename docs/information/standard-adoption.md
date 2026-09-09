---
{
  "schema": "wellmanifest.docs/document/v1",
  "id": "standard-adoption",
  "kind": "information",
  "version": 1,
  "title": "Pinned URIprocess manufacturing standard adoption",
  "status": "implemented",
  "owner": "subactor/uriprocess",
  "created": "2026-09-09",
  "updated": "2026-09-09",
  "review_after": "2026-10-09",
  "source_revision": "f29f72a3b96a2400cfcdd27205509604da3e8b27",
  "affected_repositories": ["subactor/uriprocess"],
  "evidence": [
    "https://github.com/wellmanifest/uriprocess/tree/32704f47634aa393b87f8b398a7903d719eece92",
    "repo://subactor/uriprocess/.governance/uriprocess.lock.json",
    "repo://subactor/uriprocess/tools/check_standard.py",
    "repo://subactor/uriprocess/tests/test_standard.py",
    "repo://subactor/uriprocess/Makefile"
  ]
}
---

# Pinned URIprocess manufacturing standard adoption

<!-- docs:section purpose -->
## Purpose

ADOPT [wellmanifest/uriprocess 0.1.0](https://github.com/wellmanifest/uriprocess/blob/32704f47634aa393b87f8b398a7903d719eece92/docs/information/uriprocess-standard.md)
as the canonical manufacturing contract. The standard owns requirements,
package schemas and its reference conformance checker. This project continues
to own generators, source verification, URIpack integration and runtime tooling.

<!-- docs:section scope -->
## Scope

The adoption covers both existing catalogs: two POA/Node libraries and six
native Python connectors, retaining all 21 original URI identities. It changes
neither the selected source revisions nor the package bytes or native APIs.
The metadata source revision identifies the consumer implementation base.

<!-- docs:section evidence -->
## Evidence

The source pin is `32704f47634aa393b87f8b398a7903d719eece92`; the exact
`bundle.json` SHA-256 is
`837456dbbd58f3ba9d44788a3987fd351e300167d94945ca6c999c3a4816a885`.
The projection's four files are VERSION, policy, package schema and conformance
checker. Each was read from that Git commit and compared with its bundle hash.
The lock and projection are tracked with the consumer, requiring no checkout
discovery or runtime download.

Nine consumer regressions exercise all eight real packages, verification of
every bundled file before code loading, invalid revision/digest pins, absent
or unsafe files, changed bundle membership, frozen policy readback, catalog
URI ownership, removal of original tests and bounded CLI failure. The source
standard has its own sixteen conformance cases. These tests complement the
existing upstream, installed-package, URIpack and Docker verification.

<!-- docs:section content -->
## Integration

```bash
make test-standard
python3 -B tools/check_standard.py --root /path/to/explicit/candidate
```

The default checks both tracked catalogs. An explicit candidate root may contain
either or both supported catalogs; an empty root is rejected. The returned
counts describe the catalogs actually observed. Native and POA package roots
remain unchanged, including their original manifests and entry points.

`make test` includes standard conformance. `tests/test_standard.py` also joins
ordinary unittest discovery used by the existing OneDev verification entrypoint.
The dependency on `jsonschema` uses the existing verification environment.

`tools/check_standard.py` verifies the lock, exact bundle digest, closed file
membership and every file digest before loading code. It freezes those verified
bytes and data in a temporary directory so subsequent projection changes cannot
replace the schema used by that invocation. The temporary copy is removed after
checking. Symlinks and special files are rejected using no-follow reads.

The checker compares package metadata and source hashes, checks native identity
against preserved manifests, and compares each package's full catalog coverage
and bytes. It rejects URI drift and duplicate ownership across both catalogs.
It emits the actual standard load receipt with source revision, version and
bundle digest. It executes no package code and calls neither Guard nor apply.

On failure the CLI returns code 2 and a bounded `URIPROCESS_STANDARD_REJECTED`
diagnostic. A successful result retains `execution_authority=false` and
`production_verified=false`; the standard's per-package result additionally
denies upstream, behavior, Guard and publication authority claims.

### Updating the standard

Change normative requirements, schemas or checker code in the owning
`wellmanifest/uriprocess` repository. Publish a new immutable version and its
bundle, then update this lock and exact projection in a material adoption PR.
Run both profiles against actual packages and preserve the existing verification
gates. Do not edit the projected checker or author another requirements catalog
inside this repository.

<!-- docs:section limitations -->
## Limits of adoption evidence

This is a declared immutable source adoption and test integration. The local
receipt proves bundle consistency with the supplied lock; it does not
authenticate a Git revision remotely or make that PR-controlled lock an
independent operator policy pin. Promotion to mandatory protected policy
requires a separately reviewed, deployed CI pin and observed execution.

The source standard was initially published on `bootstrap/uriprocess-standard`.
That source reference is not an independent standard merge receipt. Consumer
publication retains its existing protected local OneDev and independent
Validator path, whose receipts must bind the actual PR head and current base.

Package conformance does not prove original Git identity, test execution,
license clearance, production Guard integration or completed process migration.
Those boundaries remain in the existing
[URIpack integration contract](uripack-integration.md).

<!-- docs:section next_actions -->
## Next actions

Retain this conformance check when adding selected packages. New profiles begin
in the standard owner and require real source and behavior evidence before
adoption. Independently pin the standard in operator-owned CI before claiming
mandatory protected policy enforcement; keep production migration and Guard
acceptance as separate observed outcomes.
