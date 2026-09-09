# uriprocess

HOME subactor; SHAPE runtime_service. Preserve original process URIs, source
bytes, provenance and upstream tests. New selections require an exact Git
revision and explicit files. Do not infer executable bindings from declarations.
Readiness decisions and signed catalogs do not authorize effects.

Documentation ADOPT [wellmanifest/docs 0.1.0](https://github.com/wellmanifest/docs/blob/fdb0fcaa7c606dc2503cabb71eff64d5f86ee659/docs/standard/POLICY.md),
pinned in `.governance/docs.json`. Canonical information is in
`docs/information/`, indexed by `docs/README.md`. Run the pinned checker.
This pin does not establish protected CI enforcement.

Manufacturing ADOPT [wellmanifest/uriprocess 0.1.0](https://github.com/wellmanifest/uriprocess/blob/32704f47634aa393b87f8b398a7903d719eece92/docs/information/uriprocess-standard.md).
The exact source revision and bundle digest are in
`.governance/uriprocess.lock.json`; `.governance/uriprocess/` is a verified
projection, never a second authoring source. Change the standard in its owner
repository, then explicitly update this adoption. Run `make test-standard` and
the existing upstream, install, URIpack and Docker checks. Bundle conformance
does not prove upstream identity, test execution, protected approval or deployment.
An operator-owned CI policy pin remains a separate enforcement step.

Use the inherited protected local OneDev / independent Validator publication
policy. Initial source publication does not establish independent review,
release approval, production routing or deployment. Missing profiles are gaps.
