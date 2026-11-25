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

## Code conventions

These rules sit beside the layer table. The last two are review rules; the others are checked by the goldens, the contract tests or depguard.

- **Services may depend on services, one way.** Today: `agent` → `approval`, `ledger`, `links`, `pii`, `revert`; `approval` → `links`, `revert`; `revert` → `links`; `plugin` → `links`, `status`; `status` → `handoff`. Go refuses a cycle. Before adding an edge, check whether what you need is shared wording for the agent, which belongs in `core/guidance`.
- **The consumer declares the port.** The package that calls a port defines the interface, with one method per question it asks. Where `internal/app` implements a port, the method is a one-line forward.
- **An inbound adapter only translates.** It decodes a request, calls one service and encodes the answer. A domain's MCP package exports `Tools(port, mount)`; `internal/app` composes every domain's tools in a fixed order and wraps each one once with the admin-credential refusal.
- **Code lives with its callers and its data,** not with the topic in its name. A builder that only the status report uses stays in `internal/status`, even if it talks about setup.
- **Type names that reach output never change.** The validator prints an argument struct's Go type name in MCP errors (`Key: 'confirmArgs.Database' …`), and the served goldens pin it. Never rename, export or alias an args or DTO struct, and look for `%T` and reflection before renaming any type.
- **Export only what production code outside the package calls.** No test-only exports; a test that needs internals lives in the package.
- **Tests set options before construction.** A test helper takes a `func(*Deps)` applied before the service is built; no test wires a service twice or swaps a dependency on a built service.

## Guards beyond the layer rules

Three tests in `internal/app` scan the source rather than import graphs. Each one fails on a new violation and on a stale entry in its list.

- **Config load guard** (`TestNoRootPathUsesPlainConfigLoad`): no code reads the engine config with `config.Load`, `LoadOpen` or `LoadNoFollow` directly, because a process running as root must use the hardened read, `cli.LoadEngineConfig`. It walks every non-test file in `cmd/basalt` and all of `internal/` except `internal/config`, so code in a new package stays in view. The few allowed calls are listed with the reason each is safe.
- **Credential read guard** (`TestRootCredentialReadsAreChecked`): every read of an agent's credential file, in the same files, either happens in a function that calls `pgdial.CheckForeignDSN` or is listed with the reason root never connects with what another user wrote there. `TestCredentialReaderTableIsReal` holds the table of reader functions to functions that exist.
- **Agent-facing text** (`TestAgentFacingTextIsAgentLed`): the MCP instructions, tool schemas in `api/mcp`, next steps, engine strings and the agent docs never steer an agent to a `basalt init` that takes the admin connection string anywhere but a setup page. It checks the Go strings of the packages an agent can read, so a new package that writes agent-facing text goes in its list.

## The agent domain is store-neutral

The agent's use cases (`internal/agent`, the root package) work on any store: today Postgres, later stores that do not speak SQL. They reach the store through one `agent.StoreSet` that `internal/app` builds for the store's kind, and the types its ports are written in live in `internal/core/agentstore`. A held write goes to the approval domain through the `Approvals` port in one call (`Hold`), which passes the request on to the approval's store.

- The service passes a request (`agentstore.Request`) on and records it, and never reads its text. Checking it, the texts of its refusals and the store's resource names belong to the store's `Language` (for SQL, `internal/agent/out/sqllang`).
- Resources and fields are opaque refs (`agentstore.ResourceRef`, `FieldRef`) the store makes up; the service compares them, never parses them. The store fills describe's content; the service decides what is hidden: a field the agent cannot read or that is classed SECRET, and every identity, feature and expression that touches one.
- The tools the agent is served come from the store's `Family`, and the service may read the store's `Capabilities`; it never switches on the kind.

`TestAgentDomainIsStoreNeutral` (`internal/testkit/archtest`) holds the root package's non-test files to it: no direct import of `core/sqlguard`, `platform/postgres`, the pgx packages, `lib/sqlport`, `lib/pgquerier` or squirrel, no `$1`-style placeholder or `pg_` name in a string, and no identifier with `OID`, `Attnum` or `pg_`. It fails when it scans no file, and each entry in its allowlist carries the reason it may stay. `TestStoreNeutralDomainsLinkNoStorePackage` checks its imports through every other package too (see the PII domain below). `TestDocumentStoreRunsTheAgentThroughThePorts` and the describe tests next to it run the service over an in-memory document store with a JSON filter language, through the ports only.

To add a store:

1. Name its kind in `core/action`, and the `Family` it belongs to in `internal/app` (`storeFamily`). A family that is not SQL is a new `Family` in `core/agentstore`, and its tools are a contract change first, then `internal/agent/in/agentmcp`.
2. Write its adapters: the `Language` (check a request, the refusal and step texts, resource names), `Data` (read, write, the approved write, limits), `Catalog` (resources, one resource's `agentstore.Detail`, search, the structure lines), its `Ledger`, and its PII `Classes`; `Visibility` only when the store can hide items from the agent.
3. Serve its held writes through the approval domain's store ports (see below).
4. Build the `StoreSet` for the kind in `internal/app`. Change nothing in `internal/agent`: a change there that only one store needs belongs in that store's adapter.

## The approval domain is store-neutral

The approval's use cases (`internal/approval`, the root package, and its tools in `internal/approval/in/approvalmcp`) work on any store the same way. They reach the store through one `approval.StoreSet` that `internal/app` builds (`approvalStoreSet`), with three ports: `Records` reads the ledger of the agent's held writes, `Holds` is the agent's side (preview a write, hold it) and `Proofs` is the person's side (submit a signed approval, reveal a held write's hidden rows in one call).

- The service passes the held request on unread: to the store's preview and hold as the agent sent it, and on a reveal as the binding carries it (`action.HeldRun`). It never parses a statement, and next steps name the request's arguments the way the store family's tools do (`agentstore.RequestArgs`), never `sql`. `list_pending` answers `request.kind` from the held write.
- The service decides on the store's typed refusals (`action.ApprovalRefusalError` and its `ApprovalReason`), never on a store's error codes or texts. Each store's adapter maps its own answers to a reason per call (for Postgres, `internal/platform/postgres/store/approvals.go`). A hold's refusal the agent records comes as a `HoldRefusalError`, and the store marks an error of its preview run as `action.PreviewFailedError`.
- The hold's own rules (no rows now, `guardmodel.MaxHeldLinesBytes`) are Basalt's, checked by the service on the preview's lines; which fields a write binds is the store's.
- The store checks the person's signature itself: the wiring refuses a store whose `Capabilities` lack `InStoreSignatureCheck`, and the service refuses a set with a nil port (`TestNewServiceRefusesAStoreWithoutSignatureCheck`, `TestNewRefusesAStoreSetWithANilPort`).

`TestApprovalDomainIsStoreNeutral` (`internal/testkit/archtest`) holds the root package's and `approvalmcp`'s non-test files to it: no direct import of `core/sqlguard`, `platform/postgres`, the pgx packages, `lib/sqlport`, `lib/pgquerier` or squirrel; no `guidance.LedgerCode`, `StoreDetail` or `StoreError`, no `guardmodel.Code*`, `*Refused` or `Reveal*`, no `approval.RequestSQL` and no `action.StoreError`, matched by exact name through the file's imports (so `guidance.CodeStoreError`, the answer for a write that changes no rows now, and `guardmodel.MaxHeldLinesBytes` stay); no identifier with `SQLState`, `OID` or `pg_`; and no `pg_` or the literal `"sql"` in a string. Its allowlist is empty. `TestStoreNeutralDomainsLinkNoStorePackage` checks its imports through every other package too (see the PII domain below). `TestApprovalStoreRuleCatchesViolations` proves each ban.

To add a store to approvals: write its `Records`, `Holds` and `Proofs` adapters, mapping its answers to the approval reasons per call, its family's `RequestArgs`, and build its `StoreSet` in `internal/app`. Change nothing in `internal/approval`.

## The revert domain is store-neutral

The revert's use cases (`internal/revert`, the root package) work on any store the same way. They reach the store through one `revert.StoreSet` that `internal/app` builds for the store's kind (`revertStoreSet`), with three ports: `Records` reads the ledger of the agent's reverts, `Undo` is the agent's side (preview, prepare, reset, apply a batch of a signed plan), and `Proofs` is the person's side (apply, rescope, reject, reveal). The set carries the store's `Limits`; a prepare runs under the store's own time limit.

- The service decides on the store's typed refusals (`action.RevertRefusalError` and its `RevertReason`), never on a store's error codes or texts. Each store's adapter maps its own answers to a reason per call (for Postgres, `internal/platform/postgres/store/revert.go`). The refusal's `Detail` is the store's text, shown verbatim where the answer shows what the store said, and `StoreCode` is the store's own code, passed on as it is.
- Resource names are the store's: the service passes the agent's `resources` on as written, and the store checks their form and that the agent wrote them (`FILTER_NAME`, `FILTER`).
- What the person signs is the same for every store: the binding text, the revert lines, `rowsHash` and a batched plan's `sampleHash` (`internal/core/revert`, `approval.RowsHash`). The store checks the person's signature itself: the wiring refuses a store whose `Capabilities` lack `InStoreSignatureCheck` (`TestNewServiceRefusesAStoreWithoutSignatureCheck`).

`TestRevertDomainIsStoreNeutral` (`internal/testkit/archtest`) holds the root package's non-test files to it: no direct import of `core/sqlguard`, `platform/postgres`, the pgx packages, `lib/sqlport`, `lib/pgquerier` or squirrel; no `guidance.LedgerCode`, `StoreDetail`, `ScopeRefusal` or `TimedOut`, no `guardmodel.Code*`, `Scope*` or `*Refused`, and no `action.StoreError`, matched through the file's imports; no identifier with `SQLState`, `OID`, `xmin` or `pg_`, and no `pg_`, `xmin` or SQLSTATE-shaped code (five digits or capitals starting with a digit, such as `57014`, as a word) in a string. Its allowlist is empty. `TestStoreNeutralDomainsLinkNoStorePackage` checks its imports through every other package too (see the PII domain below). `TestObjectStoreRevertsARunThroughThePorts`, `TestObjectStoreAppliesABatchedPlanThroughThePorts` and `TestObjectStoreRefusalsGiveThePostgresAnswers` (`internal/revert`) run the service over an in-memory versioned object store, through the MCP tools and the person's page: resources named `namespace/collection`, the store's own codes, a batched plan of more than 1000 lines, and the same answers the Postgres store's refusals give.

To add a store to reverts: write its `Records`, `Undo` and `Proofs` adapters, mapping its answers to the revert reasons per call, and build its `StoreSet` with its `Limits` in `internal/app`. Change nothing in `internal/revert`.

## The PII domain is store-neutral

The PII use cases (`internal/pii`, the root package: the class map, the observer, the dictionary scan, the classifier and the hourly check) work on any store the same way. The types its ports are written in live in `internal/core/piistore`, with the field and resource refs (`FieldRef`, `ResourceRef`) from `internal/core/agentstore`; for Postgres the adapter is `internal/platform/postgres/pgpii`.

- `Classes` reads one agent's field classes and the marks they were loaded with, the fields that need a person, and the resource that holds a field. The map's loads, its reload once per unknown resource per tick and its warnings stay in the domain, keyed by the store's opaque `FieldRef` and `ResourceRef`; an empty ref is a computed value and has no class.
- `Fields` reads one resource's IDENTIFIER fields for the scan, page by page. How to page (a key, a row position, one pass), the statement timeout and the store's error codes are the adapter's: it fails a resource the scan should skip with `piistore.ErrUnreadable` or `piistore.ErrTooSlow`. It hands a JSON value as `json.RawMessage` and any other as text, so the scan and the observer give the dictionary the same text.
- The classifier works on a field's `Kind` (Basalt's word for how its values are treated), never on the store's type name. Every adapter maps a type it cannot place, or a field with mixed types, to `KindText`, so it is sampled. The sampler is the store's; setup gets it through its `Backend`.

`TestPIIDomainIsStoreNeutral` (`internal/testkit/archtest`) holds the root package's non-test files to it: no direct import of `core/sqlguard`, `platform/postgres`, the pgx packages, `lib/sqlport`, `lib/pgquerier` or squirrel; no identifier with `OID`, `Attnum`, `SQLState`, `relkind`, `ctid` or `pg_`; and no `pg_`, `basalt_meta`, `$1`-style placeholder or SQLSTATE-shaped code in a string. Its allowlist is empty.

`TestStoreNeutralDomainsLinkNoStorePackage` runs `go list -deps` for `internal/agent`, `internal/revert`, `internal/pii`, `internal/approval` and `internal/approval/in/approvalmcp` on linux and darwin and fails when one of those store packages is among their imports at any depth, naming the import chain. Its allowlists are empty: SQL helpers that only a Postgres adapter calls live beside it in `internal/platform/postgres` (the ledger's keyset paging), never in a shared `lib` package the domains import.

To add a store to PII: write its `Classes` and `Fields` adapters and its sampler, mapping its types to a `Kind` and its errors to the two skip errors, and wire them in `internal/app` and setup's backend. Change nothing in `internal/pii`.

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
| `approval` | approvals | decision | 1 | - | `DecodeResponse`, `DecodePluginResponse`, `CheckTexts` |
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
| `textrule` | signed texts | codec | 3 | - | - |
| `setupcode` | setup | codec | 3 | `crypto/rand`, `net` | - |
| `pluginproto` | plugins | codec | 3 | - | - |
| `largevalue` | large values | codec | 3 | - | - |
| `toolresult` | agent | types | 2 | - | - |
| `servicespec` | engine service | types | 2 | - | - |
| `guidance` | agent | types | 2 | - | - |
| `agentstore` | agent | types | 2 | - | - |
| `piistore` | PII | types | 2 | - | - |

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
