# Architecture

Where code lives in this repo and which package may import which. The behaviour of every surface is fixed in [CONTRACT.md](CONTRACT.md); [docs/architecture.md](docs/architecture.md) tells how the pieces work together at runtime (one binary, the guard, how a held write reaches approval). This page is about the code layout, and a Go test enforces it (`internal/testkit/archtest`).

## Layers

```
cmd/basalt/main.go             the one binary: main() calls app.Main. Nothing else lives here.
internal/app                   the composition root: parses the command line, builds every adapter and hands it to the services; also wires the served agent (agent_*.go)
internal/<domain>              the domain's use cases (the service): the order of the steps; declares its ports; no SQL, HTTP or files
internal/<domain>/in/<name>    inbound adapters of the domain, for example <domain>cli, <domain>mcp, <domain>page. Translate a request, call the service
internal/<domain>/out/<name>   outbound adapters of the domain: files, the OS, the network. Implement the service's ports
internal/platform/<name>       shared adapters. Inbound servers: httpserver, mcpserver, pageserver, shim, cli. All the rest is outbound: postgres/*, vault, osservice, keyfile
internal/config                the engine config file
internal/core                  types, decisions, codecs; no I/O
internal/lib                   helpers with no BasaltDB knowledge
web/                           route data and embedded pages
internal/testkit               shared test fakes and the architecture test
pkg/                           public Go API: only what other repos import (setup, trustprofile, trustpin)
api/                           the contract files: proto, schemas, vectors
```

The domains are `agent`, `approval`, `engine`, `handoff`, `ledger`, `links`, `pii`, `plugin`, `revert`, `setup` and `status`. A domain has a root package (its service) and only the `in` and `out` folders it needs. For example, `internal/revert` is the revert use case, `internal/revert/in/revertmcp` and `internal/revert/in/revertpage` are its MCP tools and its signing page, and `internal/setup/out/credfiles` is the setup domain's credential file adapter.

A service never talks to Postgres, the network or the disk itself. It declares the interface it needs (a port) and an outbound adapter implements it. `internal/app` builds the adapters and passes them in. `pkg/setup` is the second composition root: another program calls it directly, with no `internal/app`, so it builds the adapters the setup service needs and passes them in. It is the only package under `pkg/` that may import an outbound adapter.

`internal/platform` holds what no single domain owns. Its inbound packages (`httpserver`, `mcpserver`, `pageserver`, `shim`, `cli`) serve a transport for every domain; every other package there is an outbound adapter that more than one domain uses, such as the Postgres store, the guard installer and the Vault client.

## Import rules

Each row lists what a package in that layer may import from this repo. Anything not listed fails `TestArchitecture` in `internal/testkit/archtest`. Which layer a package is in follows from its path: `internal/platform/{httpserver,mcpserver,pageserver,shim,cli}` and `internal/<domain>/in` are inbound; the rest of `internal/platform` and `internal/<domain>/out` are outbound; `internal/<domain>` is a service. `TestNewTreeLayers` holds that table.

| Layer | May import |
|---|---|
| lib | lib |
| web | core, lib |
| core | core, lib, api |
| config | core, lib, api |
| service | service, config, core, lib, pkg, api, web |
| outbound | outbound, config, core, lib, pkg, api, web |
| inbound | inbound, service, config, core, lib, pkg, api, web |
| app | everything |
| cmd | app, service, inbound, config, core, lib, pkg, api, web (not outbound) |
| pkg | pkg, lib; `pkg/setup` also service, core and outbound |

Three more rules sit on top of the table, all in `internal/testkit/archtest`.

- **A service imports no driver, directly or through another package.** `TestArchitecture` fails a non-test file under a domain root that imports `github.com/jackc/pgx` (including `pgconn`), `database/sql` or `net/http`: the service declares a port and an outbound adapter holds the driver. `TestServicesLinkNoDatabaseDriver` runs `go list -deps` for every domain root on linux and darwin and fails when a database driver is among the transitive imports. The one named exception is the import of `pgconn` by `pkg/trustprofile`, whose `Trust` and `Explain` take a `*pgconn.Config` as part of the public API; only that edge is skipped, and every other import of `pkg/trustprofile` is followed.
- **A platform inbound package imports no domain service.** `httpserver`, `mcpserver`, `pageserver`, `shim` and `cli` serve every domain, so none of them may import one domain's use case. What they need from a domain they take as a port that `internal/app` fills in. The packages that still break this are in the baseline (below), and the list only shrinks.
- **Only `internal/app` installs the plugin path rule.** No other non-test file calls `UsePathRules` on the plugin package; test files and the test helper packages are exempt, as they are from the layer rules.

One import that looks like it crosses a domain on purpose: `internal/approval/in/approvalmcp` imports `internal/revert/in/revertmcp` for the pending-revert item. The approval domain holds a revert (the approval service's `PendingEntry` carries a `revert.PendingRevert`), and the MCP item that lists it is the revert tool's type. It is an inbound adapter importing another inbound adapter, which the table allows.

Test files and the test helper packages (`guardtest`, `mcptest`, `passkeytest`, `pagetest`, `vaulttest`, `adaptertest`, `trustprofiletest`, `connecttest`, `stepcatalogtest`, `archtest` and the core test oracles) are exempt from the layer rules, core purity and the decision rule. The list is in the test.

Every package under `internal/` sits in one of the layers above. A new domain, or any other new top-level directory under `internal/`, needs a row here and an entry in the test.

## Guards beyond the layer rules

Three tests in `internal/app` scan the source rather than import graphs. Each one fails on a new violation and on a stale entry in its list.

- **Config load guard** (`TestNoRootPathUsesPlainConfigLoad`): no code reads the engine config with `config.Load`, `LoadOpen` or `LoadNoFollow` directly, because a process running as root must use the hardened read, `cli.LoadEngineConfig`. It walks every non-test file in `cmd/basalt` and all of `internal/` except `internal/config`, so code in a new package stays in view. The few allowed calls are listed with the reason each is safe.
- **Credential read guard** (`TestRootCredentialReadsAreChecked`): every read of an agent's credential file, in the same files, either happens in a function that calls `pgdial.CheckForeignDSN` or is listed with the reason root never connects with what another user wrote there. `TestCredentialReaderTableIsReal` holds the table of reader functions to functions that exist.
- **Agent-facing text** (`TestAgentFacingTextIsAgentLed`): the MCP instructions, tool schemas in `api/mcp`, next steps, engine strings and the agent docs never steer an agent to a `basalt init` that takes the admin connection string anywhere but a setup page. It checks the Go strings of the packages an agent can read, so a new package that writes agent-facing text goes in its list.

## Core

`internal/core` holds code that is pure: it does no I/O. It has three kinds of package.

- **decision**: a safety decision: it says what is allowed, held or refused, whether an approval or revert is valid, what its scope or plan is, whether a passkey signature verifies, or what class a piece of PII is. Services, core, `internal/config` and `internal/app` (which wires everything) call a decision's functions; adapters, `web`, `cmd` and `pkg` do not. The test checks package-level functions only; methods on a decision's types are left to review. The one exception: the Postgres store calls `sqlguard.Check`, `sqlguard.CheckRepeatable` and `sqlguard.WithRowVersions` right before it runs SQL. Any package may use a decision's types and constants, and call the functions the register lists as codec functions.
- **types**: a type that a port is written in, or a rule used by two or more callers. Anyone may import it.
- **codec**: the code for a format written down in `api/`. Anyone may import it.

Core stays pure. A package in `internal/core` does not import `os`, `io/fs`, `path/filepath`, `net` (`net/url` is fine), `net/http`, `os/exec`, `syscall`, `io/ioutil`, `math/rand`, `crypto/rand` or a database driver, does not dot-import, and does not call `time.Now`, `time.Since`, `time.Until` or `os.Getenv`. The exceptions are key and salt generation in the codecs `channel` and `setupcode`, which may import `crypto/rand`, and `setupcode`'s database address, which may import `net` for `net.JoinHostPort` only; the register below records them.

## Where does this code go

1. Does it run a use case, in steps (check, call a port, record, answer)? Put it in the service that needs it, in `internal/<domain>`.
2. Does it read or write Postgres, a file, the network or the OS? It is an outbound adapter. The service declares the port; the adapter implements it: in `internal/<domain>/out/...` when one domain uses it, in `internal/platform/...` when several do.
3. Does it turn a request from outside (an MCP call, an HTTP request, a page) into a call on one service? It is an inbound adapter in `internal/<domain>/in/...`, or in an inbound `internal/platform` package when it serves every domain (the MCP server, the page server, the shim, the CLI core).
4. Does it create adapters and connect them to services, or choose which command runs? That is `internal/app`, and `pkg/setup` for a program that calls it directly. Nowhere else.
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
| `setupcode` | setup | codec | 3 | `crypto/rand`, `net` | - |
| `pluginproto` | plugins | codec | 3 | - | - |
| `largevalue` | large values | codec | 3 | - | - |
| `toolresult` | agent | types | 2 | - | - |
| `servicespec` | engine service | types | 2 | - | - |
| `guidance` | agent | types | 2 | - | - |

## Known violations

The code does not meet every rule yet. `internal/testkit/archtest/baseline/` lists what is left, one file per importing package. A violation that is not listed fails the test, and so does a listed one that no longer exists: remove the line when you fix it, or regenerate the files with `go test ./internal/testkit/archtest -update`. The baseline only shrinks: do not add a line to make a new violation pass.

## Where is a feature

### Reverts

| Step | Where |
|---|---|
| MCP tools `request_revert`, `preview_revert`, `revert_plan`, `apply_revert_batch` | `internal/revert/in/revertmcp/tools.go`; the use case in `internal/revert/revert_service.go`, `revert_rescope.go` |
| Next steps for the agent | `internal/revert/revert_steps.go` |
| Revert code and authorisation line | `internal/core/revert` |
| Passkey signature check | `internal/core/passkey` |
| Revert SQL, verified inside Postgres | `internal/platform/postgres/guard/revert.go`, `rescope.go`, `schema/006_reverts.sql` |
| Ledger side of a revert | `internal/platform/postgres/ledger/reverts.go` |
| The person's page | `internal/platform/pageserver/pages.go`, `internal/revert/in/revertpage` |

### Approvals

| Step | Where |
|---|---|
| A write is held; the agent is told how to wait | `internal/agent/write_hold.go`, `internal/approval/approval_flow.go`, `approval_pending.go`, `internal/links/delivery_deliver.go` |
| MCP tool `list_pending` | `internal/approval/in/approvalmcp/tools.go` |
| Approval code and the line the person signs | `internal/core/approval` |
| Passkey signature check | `internal/core/passkey` |
| Approval SQL, verified inside Postgres | `internal/platform/postgres/guard/approval.go`, `schema/005_approvals.sql` |
| Ledger side | `internal/platform/postgres/ledger/approvals.go` |
| The person's page | `internal/platform/pageserver/pages.go`, `internal/approval/in/approvalpage` |
| Plugin approvals | `internal/plugin/plugin_approvals.go`, `internal/core/approval/plugin.go` |
