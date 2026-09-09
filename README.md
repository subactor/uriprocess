# uriprocess

Versioned Subactor URI process packages with source, Node packages and Docker.

| Original process URI | Package directory |
| --- | --- |
| `poa://subactor.com/process/ticket-currency/v1` | [poa/ticket-currency/subactor.com/v1](poa/ticket-currency/subactor.com/v1) |
| `poa://subactor.com/process/ticket-readiness/v1` | [poa/ticket-readiness/subactor.com/v1](poa/ticket-readiness/subactor.com/v1) |

```bash
make test-all  # Python 3, Node >=22, Docker
make pack     # npm archives in dist/, with offline installation checks
printf '%s\n' '{"ticket":{"id":"PLF-1","status":"open"}}' | \
  node poa/ticket-currency/subactor.com/v1/bin.mjs
```

These are existing decision implementations extracted from an immutable runtime
commit. They preserve the POA contracts and upstream tests. They do not execute
the full capability DAG or switch production consumers. Readiness requires a
trusted actor validator for executable decisions; the standalone JSON adapter
retains fail-closed behavior.

[Packaging, generation, verification and limitations](docs/information/process-packaging.md).

[Native Guard observation and its limits](docs/information/guard-observation.md)
uses the existing Guard API for exact-revision Git observations. It grants no
execution or publication authority.

[Native Guard export](docs/information/native-guard-export.md) adds planning,
separately admitted execution and verified package retrieval. The full local
HTTP/CLI/Docker/npm test is `make test-guard-export`; production provisioning
and independent publication are separate prerequisites.
