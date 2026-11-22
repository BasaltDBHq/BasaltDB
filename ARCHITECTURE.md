# Architecture

Where code lives in this repo and which package may import which. The behaviour of every surface is fixed in [CONTRACT.md](CONTRACT.md); [docs/architecture.md](docs/architecture.md) tells how the pieces work together at runtime (one binary, the guard, how a held write reaches approval). This page is about the code layout, and a Go test enforces it (`internal/testkit/archtest`).

## Layers

```
cmd/basalt                     CLI: flags -> app or a service. No SQL, no rules.
internal/app                   the only wiring: builds every adapter, hands it to the services
internal/adapter/inbound       mcp, shim, pages, localsetup, httpserver: translate a request, call one service
internal/service               use cases: the order of the steps; declares its ports; no SQL, HTTP or files
internal/adapter/outbound      postgres/*, vault, plugintransport/*, osservice, trustdir, updatecheck, crash
internal/config                the engine config file
internal/core                  types, decisions, codecs; no I/O
internal/lib                   helpers with no BasaltDB knowledge
web/                           route data and embedded pages
internal/testkit               shared test fakes
pkg/                           public Go API: only what other repos import (setup, trustprofile, trustpin)
api/                           the contract files: proto, schemas, vectors
```

A service never talks to Postgres, the network or the disk itself. It declares the interface it needs (a port) and an outbound adapter implements it. `internal/app` builds the adapters and passes them in.

## Import rules

Each row lists what a package in that layer may import from this repo. Anything not listed fails the test.

| Layer | May import |
|---|---|
| lib | lib |
| web | core, lib |
| core | core, lib, api |
| config | core, lib, api |
| service | service, config, core, lib, pkg, api, web |
| adapter/outbound | outbound, config, core, lib, pkg, api, web |
| adapter/inbound | inbound, service, config, core, lib, pkg, api, web |
| app | everything |
| cmd | app, service, inbound, config, core, lib, pkg, api, web (not outbound) |
| pkg | pkg, lib; `pkg/setup` also service and core |

Test files and the test helper packages (`guardtest`, `mcptest`, `passkeytest`, `pagetest`, `vaulttest`, `adaptertest`, `trustprofiletest`, `connecttest`, `archtest`) are exempt from the layer rules, core purity and the decision rule. The list is in the test.

Every package under `internal/` sits in one of the layers above. A new top-level directory under `internal/` needs a row here and in the test.

## Core

`internal/core` holds code that is pure: it does no I/O. It has three kinds of package.

- **decision**: a safety decision (what SQL is allowed, whether an approval or revert code is valid, whether a passkey signature verifies). Services, core, `internal/config` and `internal/app` (which wires everything) call a decision's functions; adapters, `cmd` and `pkg` do not. The test checks package-level functions only; methods on a decision's types are left to review. The one exception: the Postgres store calls `sqlguard.Check`, `sqlguard.CheckRepeatable` and `sqlguard.WithRowVersions` right before it runs SQL. Any package may use a decision's types and constants, and call the functions the register lists as codec functions.
- **types**: a type that a port is written in, or a rule used by two or more callers. Anyone may import it.
- **codec**: the code for a format written down in `api/`. Anyone may import it.

Core stays pure. A package in `internal/core` does not import `os`, `io/fs`, `path/filepath`, `net` (`net/url` is fine), `net/http`, `os/exec`, `syscall`, `io/ioutil`, `math/rand`, `crypto/rand` or a database driver, does not dot-import, and does not call `time.Now`, `time.Since`, `time.Until` or `os.Getenv`. The exception is key and salt generation in the codecs `channel` and `setupcode`, which may import `crypto/rand`; the register below records it.

## Where does this code go

1. Does it run a use case, in steps (check, call a port, record, answer)? Put it in the service that needs it, in `internal/service/<name>`.
2. Does it read or write Postgres, a file, the network or the OS? It is an outbound adapter. The service declares the port; the adapter in `internal/adapter/outbound/...` implements it.
3. Does it turn a request from outside (an MCP call, an HTTP request, a page) into a call on one service? It is an inbound adapter in `internal/adapter/inbound/...`.
4. Does it create adapters and connect them to services? That is `internal/app`, and nowhere else.
5. Is it a helper that knows nothing about BasaltDB (a browser opener, a time format)? `internal/lib`.
6. Is it a fake or fixture shared by tests? `internal/testkit`.
7. Is it needed by code in another repo? `pkg/`, and only that.

New code starts in the service that needs it. It moves to `internal/core` only if it is pure and one of these holds:

1. it is a safety decision;
2. it is a type a port is written in, or a rule used by two or more callers;
3. it is the codec for a format in `api/`.

A new core package adds a row to the register below, and the test fails until it does.

## Core register

Every package directly under `internal/core` has one row: its area, its kind, the rule above that admitted it (1, 2 or 3), the standard-library packages beyond the pure set that it may import, and its codec functions.

A codec function is a function of a decision package that only decodes, parses or checks the format of its input. Any layer may call it, because it decides nothing. List a function only if it is that: one that decides allowed, held, refused, valid, a scope or a plan stays a decision. Only a decision package has the column filled. The test fails if a listed function does not exist.

| Package | Area | Kind | Admitted by | Extra imports | Codec functions |
|---|---|---|---|---|---|
| `sqlguard` | SQL policy | decision | 1 | - | - |
| `approval` | approvals | decision | 1 | - | `DecodeResponse`, `DecodePluginResponse` |
| `revert` | reverts | decision | 1 | - | `ParseBinding`, `DecodeResponse` |
| `passkey` | approvals and reverts | decision | 1 | - | `PublicKeyFromXY` |
| `pii` | PII handling | decision | 1 | - | `CheckDictionarySize`, `OpenDictionary`, `NewKeys` |
| `chainpin` | ledger | decision | 1 | - | `CheckName` |
| `action` | ledger | types | 2 | - | - |
| `budget` | SQL | types | 2 | - | - |
| `guardmodel` | ledger | types | 2 | - | - |
| `pluginmodel` | plugin | types | 2 | - | - |
| `supabase` | setup | types | 2 | - | - |
| `channel` | Vault channel | codec | 3 | `crypto/rand` | - |
| `links` | links | codec | 3 | - | - |
| `linkcodec` | links | codec | 3 | - | - |
| `setupcode` | setup | codec | 3 | `crypto/rand` | - |
| `pluginproto` | plugins | codec | 3 | - | - |
| `largevalue` | large values | codec | 3 | - | - |

## Known violations

The code does not meet every rule yet. `internal/testkit/archtest/baseline/` lists what is left, one file per importing package. A violation that is not listed fails the test, and so does a listed one that no longer exists: remove the line when you fix it, or regenerate the files with `go test ./internal/testkit/archtest -update`. Do not add a line to make a new violation pass.

## Where is a feature

### Reverts

| Step | Where |
|---|---|
| MCP tools `request_revert`, `preview_revert`, `revert_plan`, `apply_revert_batch` | `internal/service/agent/tools_revert.go`, `revert.go`, `rescope.go` |
| Next steps for the agent | `internal/service/agent/revert_steps.go` |
| Revert code and authorisation line | `internal/core/revert` |
| Passkey signature check | `internal/core/passkey` |
| Revert SQL, verified inside Postgres | `internal/adapter/outbound/postgres/guard/revert.go`, `rescope.go`, `schema/006_reverts.sql` |
| Ledger side of a revert | `internal/adapter/outbound/postgres/ledger/reverts.go` |
| The person's page | `internal/adapter/inbound/pages/pages.go` |
| Command line | `cmd/basalt` |

### Approvals

| Step | Where |
|---|---|
| A write is held; the agent is told how to wait | `internal/service/agent/approvals.go`, `pending.go`, `delivery.go` |
| Approval code and the line the person signs | `internal/core/approval` |
| Passkey signature check | `internal/core/passkey` |
| Approval SQL, verified inside Postgres | `internal/adapter/outbound/postgres/guard/approval.go`, `schema/005_approvals.sql` |
| Ledger side | `internal/adapter/outbound/postgres/ledger/approvals.go` |
| The person's page | `internal/adapter/inbound/pages/pages.go` |
| Plugin approvals | `internal/service/agent/plugin_approvals.go`, `internal/core/approval/plugin.go` |
