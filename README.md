# uriprocess

Versioned Subactor URI process packages with source, Node packages and Docker.

| Original process URI | Package directory |
| --- | --- |
| `poa://subactor.com/process/ticket-currency/v1` | [poa/ticket-currency/subactor.com/v1](poa/ticket-currency/subactor.com/v1) |
| `poa://subactor.com/process/ticket-readiness/v1` | [poa/ticket-readiness/subactor.com/v1](poa/ticket-readiness/subactor.com/v1) |

Native Python packages preserve their original package metadata and URI bindings:

| Native package | URI scope | Package directory |
| --- | --- | --- |
| `urirun-connector-subactor-ticket-lifecycle` | `planfile://subactor/tickets/command/reconcile-lifecycle` | [native/subactor-ticket-lifecycle/v0.1.0](native/subactor-ticket-lifecycle/v0.1.0) |
| `urirun-connector-subactor-account-twin` | 10 existing `twin://subactor/account/query/*` routes | [native/subactor-account-twin/v0.1.0](native/subactor-account-twin/v0.1.0) |
| `urirun-connector-subactor-llm-account-hub` | 4 existing `llm-account://host/` routes | [native/subactor-llm-account-hub/v0.1.0](native/subactor-llm-account-hub/v0.1.0) |

The wildcard above abbreviates the documented route set; it is not a registered
binding. Exact routes and file hashes are in [native-catalog.json](native-catalog.json).
Run `make test-native-packages` with the explicit source, builder and output
arguments described in the integration document.

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

[Create extraction plans with uripack and verify migration](docs/information/uripack-integration.md).
The integration tests exercise real extraction with an explicitly synthetic Guard;
operational `uripack apply` requires an independently protected bridge.
`make test-native-export` additionally tests the real native Guard server using
pinned Git sources and separate disposable test identities; see the integration
document for its explicit repository and output arguments.
