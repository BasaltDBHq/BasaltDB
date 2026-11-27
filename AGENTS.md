# BasaltDB — agent guide

BasaltDB is **the action ledger for AI agents on your database**. It is not a database: data stays in the person's own Postgres. One Go binary runs next to each agent as its MCP server (the edge engine), and a guard installed in the person's Postgres (`basalt_meta`: roles, triggers, ledger) records, holds and reverts agent writes. Surfaces: **MCP tools**, the **`basalt` CLI**, and the **approval and revert pages**. There is no REST API.

**Source of truth:** the contract fixes every surface: MCP tools, the CLI, the pages and `basalt_meta`. [CONTRACT.md](CONTRACT.md) is its index, with the rules every change needs and a map of the section files under [`contract/`](contract/). Before working on the engine, the guard or the CLI, read the index and then only the section files your change touches: do not load the whole contract. Update the section file in the same PR as any change to a surface. A reference such as `(CONTRACT.md, Link secrets)` names a heading; the index says which file holds it.

## Repo quick facts

- Module: `github.com/basaltdbhq/basaltdb`
- Binary: `cmd/basalt` (CLI, engine and MCP shim in one binary)
- **Before you open a PR, and before every push:** run `make fmt` and commit what it changes, then `make lint` (0 issues). CI fails on gofumpt and goimports drift, so unformatted code does not merge.
- **The gate is GitHub CI:** a pull request merges only when the `check` job of `.github/workflows/ci.yml` is green. It needs the lint, vet, script, secret scan and test jobs (the test shards run against Postgres) and the container, systemd, darwin archive and macOS smoke jobs; the manual release end-to-end job is not part of it. `make ci` (see `make help`) runs a local subset: lint, vet, dead code, the shard check, the script checks, the portal build and the race tests.
- **Commits and PR titles:** Conventional Commits `type(scope): message`, lowercase imperative, no trailing period.
- **Stack conflicts:** update a PR branch by merging its **base branch into the PR head** (`git checkout <pr-branch> && git merge origin/<base>`, resolve conflicts, commit the merge). Do **not** rebase and do **not** force-push. Work **bottom-up** through the stack (merge into the lowest conflicted PR first, then the next).
- Never push to `master` directly.

## Layout

Where code goes and which package may import which: [ARCHITECTURE.md](ARCHITECTURE.md). A Go test enforces it.

```
cmd/basalt     the one binary: main.go calls app.Main
internal/      app (wiring), one folder per domain (use cases, with in/ and out/ adapters), platform, core, lib, config, testkit
pkg/           public Go API for other repos: setup, trustprofile (with its test helper trustprofile/trustprofiletest), trustpin
docs/          user guides: install, approving, MCP clients, releasing
scripts/       release and packaging scripts
```

---

## Product rules that shape code

- The engine is the first filter; **the database is the boundary**. Anything that must hold whatever path a write takes belongs in the guard (roles, grants, triggers in `basalt_meta`), not only in the engine.
- Agents never approve and never revert. Approve and revert require a P-256 passkey signature verified **inside Postgres**.
- If the guard cannot record or evaluate an agent's write, that write fails. Writes by people and the app are never blocked.
- The admin credential is used once by `basalt init` and never stored. The engine holds only the agent's scoped credential.

## Wire format

- Normative rules live in **[CONTRACT.md](CONTRACT.md)** and the section files it lists: camelCase JSON keys, **SCREAMING_SNAKE_CASE** enum values everywhere (Go identifiers stay PascalCase: `StatusApplied = "APPLIED"`), UUIDv7 ids, RFC 3339 UTC timestamps, the change record, error codes, MCP tools.
- **Events are CloudEvents.** Anything BasaltDB emits as an event, to a plugin or outside the engine, is a CloudEvents 1.0 event in its JSON form (one event: `application/cloudevents+json`; several: the JSON batch, `application/cloudevents-batch+json`). Today: the notifier messages `feed/1` and `deliver/1` ([CONTRACT.md, Notifier messages](contract/plugins-runtime.md#notifier-messages)). Not events: ledger rows and other stored records in Postgres, tool results, CLI output, error bodies, and approval and revert requests and responses. The envelope uses the standard's attribute names (`specversion`, `datacontenttype`), `type` is a reverse-DNS name under `dev.basaltdb.` that names what happened (never the hook that carries it; nothing the engine emits is named after the Vault, whose prefix is reserved for the Vault's own events), and `id` is the same on every redelivery; the camelCase and SCREAMING_SNAKE_CASE rules apply inside `data`. No extension attributes.
- **CLI flag values** a person types are lowercase kebab-case (`--review=changed|all`). They are an input spelling only: anything stored, sent on the wire or written to the ledger uses the SCREAMING_SNAKE_CASE enum it maps to. Every flag with a fixed set of values has an explicit default value (no empty-string sentinel).
- **Actionable errors:** every error body and every result the agent must act on tells it what to do next (`nextSteps`, first step first) and, when the person must know or act, what to tell them (`personMessage`). A person's step is a link to a page, never a `basalt` command; a setup job is the agent's `basalt init --agent NAME`, which prints that link. Commands never carry `--config`, saved flags or a secret. No bare error strings to agents. A new code, reason or non-success result needs its entry in `api/mcp/errors/next-steps.json` ([CONTRACT.md, Next steps](contract/next-steps.md#next-steps)).
- **Contract first:** a new MCP tool, a tool schema change, a new error code, or a new `basalt_meta` table or function lands in a **contract-only PR** first (schemas under `api/mcp/`, `CONTRACT.md` or its section file under `contract/`, contract test). No implementation in the same PR unless CI needs it.
- Named types for anything (de)serialized; separate DTOs (`FromDomain` mappers) from domain structs.

## Lists (MCP tools and CLI)

- Every list is paginated; **no unbounded lists**. Cursor (keyset) pagination only, **no offset**.
- Arguments: **`limit`** (default 50, max 200; default and clamp in the handler, repos trust the clamped value), **`cursor`** (opaque base64url of the keyset; id-only by default since UUIDv7 is time-ordered), **`sort`** (whitelisted field, `-` prefix for desc, default `-id`), filters as explicit named arguments.
- Unknown arguments are rejected, never silently ignored.
- MCP result `{ "items": [...], "nextCursor": "..." }`; CLI prints the next cursor on **stderr**.
- One named params struct per list in its feature package, embedding **`pagination.Params`**, with `validate` tags, passed **by value** through every layer (`svc.ListChanges(ctx, params)` → `repo.ListChanges(ctx, params)`). No positional argument lists or ad-hoc maps past the handler. The same struct backs the MCP tool arguments and CLI flags.

## IDs

- **UUIDv7** for all app-generated ids (`github.com/google/uuid` `NewV7`, via `internal/lib/uniqueid`). `uuid` in Postgres, canonical text on the wire. Default list cursor is id-only (time-ordered).

## SQL

- **DML and queries we write** (ledger, approvals, catalog reads): query builder **github.com/Masterminds/squirrel** with **`PlaceholderFormat(sq.Dollar)`**. Plain SQL strings only for: CTEs, complex aggregations, catalog queries that squirrel cannot express, DDL, triggers and PL/pgSQL. Each raw-SQL site gets a one-line comment saying why.
- **Agent SQL** is never rewritten by string concatenation. It is parsed with `libpg_query` (pure-Go wasm build), classified, and refused or run as given with bound parameters. Two exceptions, both through the parse tree and deparsed, never by concatenation. First, for recorded reads (M1.5): `query` appends version columns (`xmin` and the primary key of guarded tables in the `FROM`), strips them from the result, and records the agent's own text. If that rewritten statement fails to plan, the original runs as given and the read is recorded without versions. Second, for held writes: a write held for approval has its time functions (`now()`, `current_timestamp` and the others in `sqlguard.PlanTimes`) replaced by typed literals that Postgres evaluated once. An `INSERT` without a column list also gets the columns it leaves to such time defaults (`sqlguard.PlanTimes`, `Apply`). The rewritten statement is the one held, approved and applied. When the agent sends its own text again, `sqlguard.FixedFrom` must show the held statement is exactly that rewrite.
- **DDL, triggers, PL/pgSQL** (the guard install): not squirrel. The guard's schema lives in **`.sql` files under `internal/platform/postgres/guard/schema/`** (embedded, run in name order; files `001` to `011` are schema version 1, and each later version adds its own files: 15 versions today, `guard.LatestVersion`). A file a release shipped never changes (`schema/released.sha256`, checked by a test); a guard change is a new file and a new version, with its section in [the schema versions](contract/basalt-meta-schema-versions.md); other install SQL is backtick SQL in Go with **`fmt.Sprintf` limited to validated identifiers** (quote with `sqlident.Quote` from `internal/lib/sqlident`, the one always-quote function; `TestOneIdentifierQuoter` refuses another quote-doubling helper or `pgx.Identifier`), readable for humans; no string-slice soup in install code.
- Everything installed lives in `basalt_meta` and must be removable with `DROP SCHEMA basalt_meta CASCADE`.
- Every `basalt_meta` function declares `SET search_path = pg_catalog, pg_temp` (`pg_temp` last, or the caller's temporary tables shadow the catalog) and writes catalog relations as `pg_catalog.<name>` and the guard's own tables, views, types and functions as `basalt_meta.<name>`, so no name depends on `search_path`. Tests in `internal/platform/postgres/guard/search_path_test.go` hold every function to it. Install SQL is idempotent. Session settings use the `basalt.` prefix with `SET LOCAL`.
- Open every Postgres connection (pool or single) through **`internal/platform/postgres/pgdial`**, never `pgx.Connect` or `pgxpool.ParseConfig` directly: it sets pgx `QueryExecModeExec` so Basalt works through transaction-mode poolers (Supavisor 6543, PgBouncer).
- Business logic stays in Go except what must be enforced in the database (the guard). Guard triggers are the only triggers we install, and they act only when `pg_has_role(session_user, 'basalt_agents', 'USAGE')` (not `MEMBER`: from Postgres 16 the admin who created the roles is a non-inheriting member).
- **`COUNT(id)`**, never `COUNT(*)`. Prefer **`EXISTS (SELECT 1 …)`** over a count when only presence matters. Forward-only `basalt_meta` migrations; never edit an applied one.

## Review rules (apply to all new and changed code)

Read **this file before implementing**; do not introduce conventions that conflict with it.

- **SQL:** squirrel with `sq.Dollar` for DML; `.sql` files under `internal/platform/postgres/guard/schema/`, or backtick SQL with validated identifiers, for DDL and triggers.
- **Magic numbers:** name them; **`mnd`** is enabled in CI. Use named constants and a short comment when helpful (e.g. Postgres identifier max length **`NAMEDATALEN` − 1**, the 10/50 row limits).
- **Control flow:** early returns and flat structure over deep nesting; type asserts **`if v, ok := x.(T); !ok { return err }`**. No silent skip on a failed assertion unless intentional and **commented**.
- **DRY:** do not copy-paste the same non-trivial block across branches in a function; extract a small private helper when the same logic appears twice or more. **Mandatory** for reviews and audits.
- **Early return:** prefer guard clauses over nested `if` blocks; invert conditions to return early and keep the happy path flat. **Mandatory** for reviews and audits.
- **Agents:** cloud and coding agents must **read AGENTS.md** first and must **not** invent conflicting patterns.
- **Checked by review only:** these rules in this file have no linter or test, so a reviewer checks them: named DTO types, constructors that panic on a nil dependency, struct-tag validation, time-based code that takes `now`, the spelling and defaults of CLI flag values, the `basalt-` header prefix, `cmd/basalt` holding only `main.go`, and the nightly job's package list. [ARCHITECTURE.md](ARCHITECTURE.md) says which architecture rules are checked and which are review.

## Go code

- **No `else` by default.** Set the default first and override in an `if`, or return early. Prefer `switch` over if/else-if chains. `else` only when there is no clean alternative. Enforced via revive (`early-return`, `indent-error-flow`, `superfluous-else`).
- MCP tool handlers and CLI commands: **parse → validate → one service call → map DTO → render**. No business logic and no repos in handlers.
- Constructors panic on nil required deps; optional deps get a no-op implementation; no `if x != nil` guards at call sites.
- Errors that an agent or the person must act on follow the actionable-errors contract above: a stable code, `nextSteps` and, when needed, `personMessage`, with the entry in `api/mcp/errors/next-steps.json`. There is no shared error type.
- Struct-tag validation (go-playground/validator) over inline checks.
- Consumer-defined interfaces in the package that uses them.
- Determinism: anything time-based takes `now func() time.Time`.
- Release binaries are static and cross-compiled (`CGO_ENABLED=0`). Do not add cgo dependencies.

## Listeners and local sockets

- The engine serves agents over a **Unix socket per agent**; the agent is identified by the socket plus the peer OS user. Socket files and the credential file are readable only by the engine's OS user (and the socket by the agent's user where needed).
- Besides the person's Postgres, the engine connects out to: the Vault, over its WebSocket, only when `vault` is `ON` ([CONTRACT.md, Vault channel](contract/vault-channel.md#vault-channel)); GitHub's releases API for the update check (`internal/status/out/updatecheck`, [CONTRACT.md, Update notice](contract/update-notice.md#update-notice); off when `BASALT_UPDATE_CHECK` is `off`, `0`, `false` or `no`); the portal, once a day when the engine's pages are on the portal, to compare its pages with the ones the binary embeds (`internal/status/portalcheck.go`); the connect service, while a connect-only setup code waits for its address ([CONTRACT.md, The address hand-off](contract/connect.md#the-address-hand-off)); the address pasted on the connect page for a connect-only code, which the engine probes before the person confirms it: it reads the certificate chain (`internal/handoff/out/handoffnet`) and tries a login with a random password that cannot sign in (`internal/handoff/probe.go`), so it learns whether it can reach the database; it logs in with the agent's credential only after the person confirms the database; and a plugin served over the network (`internal/plugin/out/plugintransport`). Nothing the Vault sends is trusted: it may make a session fail, never make the engine accept anything.
- Any HTTP listener (the approval and revert pages, when served locally) defaults to loopback. Host-empty addresses (`:8080`, `0.0.0.0`, `::`) bind every interface. Plaintext on a non-loopback bind is **refused** unless TLS cert and key are set or the operator explicitly opts in to insecure plaintext. Hostnames (including `localhost`) are not trusted by name: policy is the address actually bound. Listen policy uses the bind address only; it never trusts `X-Forwarded-For`, `Forwarded` or `X-Real-IP`.
- Pages apply the Host, Origin and security-header hardening of `internal/lib/httpsec`.
- Custom HTTP headers use the lowercase **`basalt-`** prefix; do **not** register new **`X-`** headers. Keep standard names unchanged.

## Testing

- `testing` + **testify/require**; non-storage dependencies are replaced by small in-repo fakes (`guardtest`, `vaulttest`, `passkeytest`, `pagetest`, `mcptest`), not generated or testify mocks. mockery v3 is configured (`.mockery.yml`, `make mocks`) but generates nothing yet and is not installed by `make deps`; `make mocks` installs it on first use.
- Guard, ledger and catalog code is tested against a **real Postgres** (`BASALTDB_TEST_POSTGRES_URL`; locally a Docker container). Tests create their own schema or database and clean up. Mocks only for non-storage deps.
- Security properties (agent cannot approve, cannot write without intent, cannot bypass row limits) get explicit tests that run as the agent role.
- **`-race`** on every test run. Exhaustive loops in `internal/core/pii` (the million-value dictionary, every NFKC character) run sampled or smaller by default; `BASALTDB_TEST_FULL=1 go test -race ./internal/core/pii/... ./internal/pii/...` runs them at full size (slow: run it before changing the dictionary or normalizer). `.github/workflows/nightly-full.yml` runs that command every night and on demand (workflow_dispatch); a failure fails the scheduled run. A package that adopts the flag is added to that job.

## Tooling

- **Makefile** is the entry point (`.misc/make/tools.Makefile` pins tools into `./bin`, `make help` via `help.Makefile`). Targets include `help`, `deps`, `lint`, `fmt`, `vet`, `test`, `test-cover`, `build`, `mocks`, `deadcode`, `ci`.
- CI calls the same **`make`** targets for lint, vet, dead code, the script checks and the tests; `make ci` runs those locally, but only GitHub's `check` job is the gate.
- `make check-provider-roots` reads each built-in trust profile under `internal/core/trustprofile/profiles/` (Supabase, Amazon RDS), downloads each roots file from the profile's `source` and compares it with the file's pinned SHA-256. It needs the network and is not in `make ci`; run it before a release. When it fails, check the change is only new roots from the provider, replace the file, and update its `sha256` in the profile and its pin and count in `internal/core/trustprofile/builtin_test.go`. A new provider is a new profile there: a JSON file and its PEM files, no Go code.
- `make deadcode` (in `make ci` and the CI lint job) runs `deadcode` for linux and darwin on `cmd/basalt` and `internal/testkit/pkgroot`, which calls the public API under `pkg/`. The result must equal `scripts/deadcode-allowlist.txt`, which only shrinks: delete new dead code instead of listing it, and delete a line when its function is gone or gets a caller. A new exported function under `pkg/` gets a call in `pkgroot`. `pkgroot` may import only `pkg/` packages, and every module package must be reached by a root unless the script names it as a test helper or a package with no functions.
- **golangci-lint** v2 (pinned in `tools.Makefile`); config in `.golangci.yml`; fix all findings; `//nolint` only with the specific linter and an explanation.
- Do not commit local `data/`, `tmp/` or credentials.
