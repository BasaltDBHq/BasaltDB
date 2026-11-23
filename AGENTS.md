# BasaltDB — agent guide

BasaltDB is **the action ledger for AI agents on your database**. It is not a database: data stays in the person's own Postgres. One Go binary runs next to each agent as its MCP server (the edge engine), and a guard installed in the person's Postgres (`basalt_meta`: roles, triggers, ledger) records, holds and reverts agent writes. Surfaces: **MCP tools**, the **`basalt` CLI**, and the **approval and revert pages**. There is no REST API.

**Source of truth:** the contract fixes every surface: MCP tools, the CLI, the pages and `basalt_meta`. [CONTRACT.md](CONTRACT.md) is its index, with the rules every change needs and a map of the section files under [`contract/`](contract/). Before working on the engine, the guard or the CLI, read the index and then only the section files your change touches: do not load the whole contract. Update the section file in the same PR as any change to a surface. A reference such as `(CONTRACT.md, Link secrets)` names a heading; the index says which file holds it.

## Repo quick facts

- Module: `github.com/basaltdbhq/basaltdb`
- Binary: `cmd/basalt` (CLI, engine and MCP shim in one binary)
- **Before you open a PR, and before every push:** run `make fmt` and commit what it changes, then `make lint` (0 issues). CI fails on gofumpt and goimports drift, so unformatted code does not merge.
- **CI locally:** `make help`, then `make ci` (lint, vet, release-script checks, race tests). Remote GitHub CI is not a gate; `make ci` passing locally is.
- **Commits and PR titles:** Conventional Commits `type(scope): message`, lowercase imperative, no trailing period.
- **Stack conflicts:** update a PR branch by merging its **base branch into the PR head** (`git checkout <pr-branch> && git merge origin/<base>`, resolve conflicts, commit the merge). Do **not** rebase and do **not** force-push. Work **bottom-up** through the stack (merge into the lowest conflicted PR first, then the next).
- Never push to `master` directly.

## Layout

Where code goes and which package may import which: [ARCHITECTURE.md](ARCHITECTURE.md). A Go test enforces it.

```
cmd/basalt     the one binary
internal/      engine, guard install, MCP transport, CLI internals
pkg/           shared libraries (uniqueid, pagination, …)
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
- **Agent SQL** is never rewritten by string concatenation. It is parsed with `libpg_query` (pure-Go wasm build), classified, and refused or run as given with bound parameters. One exception, for recorded reads (M1.5): `query` appends version columns (`xmin` and the primary key of guarded tables in the `FROM`) through the parse tree and deparses, strips them from the result, and records the agent's own text. If that rewritten statement fails to plan, the original runs as given and the read is recorded without versions.
- **DDL, triggers, PL/pgSQL** (the guard install): not squirrel. The guard's schema lives in **`.sql` files under `internal/adapter/outbound/postgres/guard/schema/`** (embedded, run in name order; one schema version, 1); other install SQL is backtick SQL in Go with **`fmt.Sprintf` limited to validated identifiers** (quote with `pgx.Identifier{…}.Sanitize()` or equivalent), readable for humans; no string-slice soup in install code.
- Everything installed lives in `basalt_meta` and must be removable with `DROP SCHEMA basalt_meta CASCADE`.
- Every `basalt_meta` function declares `SET search_path = pg_catalog, pg_temp` (`pg_temp` last, or the caller's temporary tables shadow the catalog) and writes catalog relations as `pg_catalog.<name>` and the guard's own tables, views, types and functions as `basalt_meta.<name>`, so no name depends on `search_path`. Tests in `internal/adapter/outbound/postgres/guard/search_path_test.go` hold every function to it. Install SQL is idempotent. Session settings use the `basalt.` prefix with `SET LOCAL`.
- Open every Postgres connection (pool or single) through **`internal/platform/postgres/pgdial`**, never `pgx.Connect` or `pgxpool.ParseConfig` directly: it sets pgx `QueryExecModeExec` so Basalt works through transaction-mode poolers (Supavisor 6543, PgBouncer).
- Business logic stays in Go except what must be enforced in the database (the guard). Guard triggers are the only triggers we install, and they act only when `pg_has_role(session_user, 'basalt_agents', 'USAGE')` (not `MEMBER`: from Postgres 16 the admin who created the roles is a non-inheriting member).
- **`COUNT(id)`**, never `COUNT(*)`. Prefer **`EXISTS (SELECT 1 …)`** over a count when only presence matters. Forward-only `basalt_meta` migrations; never edit an applied one.

## Review rules (apply to all new and changed code)

Read **this file before implementing**; do not introduce conventions that conflict with it.

- **SQL:** squirrel with `sq.Dollar` for DML; `.sql` files under `internal/adapter/outbound/postgres/guard/schema/`, or backtick SQL with validated identifiers, for DDL and triggers.
- **Magic numbers:** name them; **`mnd`** is enabled in CI. Use named constants and a short comment when helpful (e.g. Postgres identifier max length **`NAMEDATALEN` − 1**, the 10/50 row limits).
- **Control flow:** early returns and flat structure over deep nesting; type asserts **`if v, ok := x.(T); !ok { return err }`**. No silent skip on a failed assertion unless intentional and **commented**.
- **DRY:** do not copy-paste the same non-trivial block across branches in a function; extract a small private helper when the same logic appears twice or more. **Mandatory** for reviews and audits.
- **Early return:** prefer guard clauses over nested `if` blocks; invert conditions to return early and keep the happy path flat. **Mandatory** for reviews and audits.
- **Agents:** cloud and coding agents must **read AGENTS.md** first and must **not** invent conflicting patterns.

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
- The engine's one outbound connection is its WebSocket to the Vault (M3.5, CONTRACT.md, Vault channel), only when `vault` is `ON`. Nothing the Vault sends is trusted: it may make a session fail, never make the engine accept anything.
- Any HTTP listener (the approval and revert pages, when served locally) defaults to loopback. Host-empty addresses (`:8080`, `0.0.0.0`, `::`) bind every interface. Plaintext on a non-loopback bind is **refused** unless TLS cert and key are set or the operator explicitly opts in to insecure plaintext. Hostnames (including `localhost`) are not trusted by name: policy is the address actually bound. Listen policy uses the bind address only; it never trusts `X-Forwarded-For`, `Forwarded` or `X-Real-IP`.
- Pages apply the `websec` Host, Origin and security-header hardening.
- Custom HTTP headers use the lowercase **`basalt-`** prefix; do **not** register new **`X-`** headers. Keep standard names unchanged.

## Testing

- `testing` + **testify/require**; non-storage dependencies are replaced by small in-repo fakes (`guardtest`, `vaulttest`, `passkeytest`, `pagetest`, `mcptest`), not generated or testify mocks. mockery v3 is configured (`.mockery.yml`, `make mocks`) but generates nothing yet and is not installed by `make deps`; `make mocks` installs it on first use.
- Guard, ledger and catalog code is tested against a **real Postgres** (`BASALTDB_TEST_POSTGRES_URL`; locally a Docker container). Tests create their own schema or database and clean up. Mocks only for non-storage deps.
- Security properties (agent cannot approve, cannot write without intent, cannot bypass row limits) get explicit tests that run as the agent role.
- **`-race`** on every test run. Exhaustive loops in `internal/core/pii` (the million-value dictionary, every NFKC and ignorable character, the false-positive tour) run sampled or smaller by default; `BASALTDB_TEST_FULL=1 go test -race ./internal/core/pii/...` runs them at full size (slow: run it before changing the tokenizer, dictionary or normalizer). `.github/workflows/nightly-full.yml` runs that command every night and on demand (workflow_dispatch); a failure fails the scheduled run. The `TestClassify*` tests in `cmd/basalt` also honour it (a 12-customer fixture by default, all 200 with the flag) and run in that job too. A package that adopts the flag is added to that job.

## Tooling

- **Makefile** is the entry point (`.misc/make/tools.Makefile` pins tools into `./bin`, `make help` via `help.Makefile`). Targets include `help`, `deps`, `lint`, `fmt`, `vet`, `test`, `test-cover`, `build`, `mocks`, `ci`.
- CI calls the same **`make`** targets; "run exact CI steps" means `make ci`.
- `make check-provider-roots` reads each built-in trust profile under `pkg/trustprofile/profiles/` (Supabase, Amazon RDS), downloads each roots file from the profile's `source` and compares it with the file's pinned SHA-256. It needs the network and is not in `make ci`; run it before a release. When it fails, check the change is only new roots from the provider, replace the file, and update its `sha256` in the profile and its pin and count in `pkg/trustprofile/builtin_test.go`. A new provider is a new profile there: a JSON file and its PEM files, no Go code.
- **golangci-lint** v2 (pinned in `tools.Makefile`); config in `.golangci.yml`; fix all findings; `//nolint` only with the specific linter and an explanation.
- Do not commit local `data/`, `tmp/` or credentials.
