# Architecture

A five-minute map of the code for someone new to it. The exact behaviour of every surface is fixed in [CONTRACT.md](../CONTRACT.md); the code and review rules are in [AGENTS.md](../AGENTS.md). This page says where things are.

## One binary, three places it runs

BasaltDB is one Go binary, `basalt` (`cmd/basalt`), plus a schema installed in the person's Postgres. The same binary plays three roles.

- **Setup command.** `basalt init` is what an agent runs to start setup, a guard update, a repair or a removal. It prints one link and the person finishes on a page. These live in `cmd/basalt`.
- **Engine.** `basalt engine` is a long-running service on the agent's machine, running as its own OS user. It serves each agent over a Unix socket, checks the agent's SQL, and holds that agent's scoped Postgres credential. It is the first filter, not the boundary. Code: `internal/engine`.
- **MCP shim.** `basalt mcp --agent NAME` is the process an MCP client starts. It only relays stdio to the engine's socket. It holds no credential and parses no SQL. Code: `internal/shim`.

The fourth piece is not Go. The **guard** is the `basalt_meta` schema in the person's Postgres: roles, row triggers, the ledger and the functions that verify approvals. It is what holds whatever path a write takes. Its SQL is in `internal/guard/schema/*.sql`, embedded in the binary and run in name order; `internal/guard` installs it and makes the calls the engine needs inside an agent's transactions.

```
MCP client --stdio--> basalt mcp (shim) --unix socket--> basalt engine --agent credential--> Postgres
                                                                                              basalt_meta (guard)
person --> setup page (admin credential, once) --------> engine or connect service --> Postgres
person --> approval / revert page (passkey) -----------> engine or relay --> basalt_meta checks the signature
```

## How a held write reaches approval, and how it is reverted

1. The agent calls the `write` tool. The engine parses the statement (`internal/sqlguard`), refuses what the policy does not allow, and runs the rest on the agent's credential through the guard, inside a transaction that carries the agent's stated intent.
2. The guard's row triggers record old and new rows in the ledger in the same transaction and count rows, cascades included. A write over the row limit, and every `DELETE`, raises an error that the guard turns into a hold instead of a change.
3. The engine previews the rows, stores the hold, and answers `APPROVAL_REQUIRED` with a link. The agent hands the link to the person (`internal/links`, `internal/engine/agent`).
4. The person opens the page and signs with a passkey. The pages are static files in `web/`, served by the engine on a loopback listener (`internal/engine/pages`) or by a hosted portal. The page and whatever carries the signed result are not trusted.
5. Postgres verifies the P-256 signature in `basalt_meta.submit_approval`. Go has a mirror of that check (`internal/passkey`) for early feedback, but only Postgres's check counts. `internal/approval` encodes the codes that travel between the engine, the page and the relay.
6. The agent repeats the `write` with the approval id, and the engine applies exactly what was previewed. If the rows changed meanwhile, it is refused.

A revert follows the same path with one difference: an agent can only prepare it (`request_revert`), and the person signs. `basalt_meta.apply_revert` verifies the signature and writes a new change that restores the old values. It never edits history, and a row someone changed after the agent is skipped and reported, not overwritten. Code: `internal/revert` for the codes, `internal/guard/schema/006_reverts.sql` for the apply.

## Package map

Start with `cmd/basalt/main.go` to see how commands are dispatched, then follow one command into `internal/`.

### `cmd/basalt`

The whole CLI: one file or a few per command (`init.go`, `approve.go`, `revert.go`, `engine.go`, `status.go`, ...). Handlers parse flags, validate, make one service call and print. Business logic stays out of them.

### `internal/`: the engine and what it serves

| Package | What it does |
|---|---|
| `engine` | The engine: sockets, peer checks, config, service install, Vault connection. Subpackages: `agent` (the tool services, start here for an MCP tool), `pages` (local setup, approval and revert pages), `person` (plugin approvals behind `request_plugin`), `config`, `service`, `peercred`, `upkeep`, `piidict`. |
| `mcp` | A minimal MCP server over JSON-RPC 2.0. Used by the engine and its tests. |
| `shim` | The `basalt mcp` relay. |
| `sqlguard` | Parses one agent statement with libpg_query and classifies or refuses it. |
| `action` | Plain structs for runs, reads, writes and refusals, with no database in them. |
| `store/postgres` | Maps `action` types to Postgres and the guard. The adapter between the agent service and the database. |
| `guard` | Installs and calls `basalt_meta`. SQL is in `guard/schema`. |
| `ledger` | Reads the ledger the way an agent may, through the agent views. Backs `run_history` and `list_runs`. |
| `pgdial`, `pgcatalog` | Opening every Postgres connection (works through poolers), and reading the catalog. |

### `internal/`: approvals, reverts and pages

| Package | What it does |
|---|---|
| `approval`, `revert` | The bytes of approval and revert codes, binding text and request links. |
| `passkey` | WebAuthn P-256 verification, mirroring the check in Postgres. |
| `links`, `linkcodec`, `server`, `websec` | Building page links, encoding long requests, listener policy, and Host/Origin/header hardening. |
| `largevalue`, `resultsize` | Keeping large values and large results within what a call or a link can carry. |

### `internal/`: Vault, privacy and support

| Package | What it does |
|---|---|
| `vault`, `channel` | The engine's one optional outbound connection to the Vault, and its encrypted session. |
| `portalverify` | Checks that the hosted portal serves the same pages as the binary embeds (run by the release workflow, `make portal-verify`). |
| `pii`, `logredact` | PII detection primitives, and keeping link secrets out of logs. |
| `setupcode`, `setuprun`, `localsetup` | The connect-only setup code a bot's `basalt init --remote` makes, running a setup, and the local setup page's jobs. |
| `chainpin` | Remembers the last ledger chain head a reader verified, to catch rewritten history. |
| `crash`, `updatecheck`, `buildinfo` | Local crash reports, the new-release notice, and the version. |

### `pkg/`

Small libraries with no BasaltDB policy in them.

| Package | What it does |
|---|---|
| `pagination` | The `limit`, `cursor` and `sort` parameters every list shares, and keyset cursors. |
| `uniqueid` | UUIDv7 ids. |
| `wiretime` | Rewrites `timestamptz` values into the wire format (RFC 3339, UTC, `Z`). |

### Other top-level directories

| Directory | What is in it |
|---|---|
| `api/mcp` | JSON Schemas for tools, approvals, links and errors, and the contract tests that hold them to CONTRACT.md. |
| `web` | The static approval, revert and passkey pages. |
| `docs` | Guides for people who use BasaltDB. |
| `scripts` | Release and packaging scripts. |

## Where to start

- **Adding or changing an MCP tool:** the contract first (`api/mcp`, CONTRACT.md), then `internal/engine/agent`.
- **Changing what the guard enforces:** a new numbered file in `internal/guard/schema`, never an edit to an applied one.
- **Changing a CLI command:** its file in `cmd/basalt`, and the CLI section of the contract (`contract/cli.md`).
- **Changing what an agent may run:** `internal/sqlguard`.
- **Changing a signing page:** `web/`, and the codes in `internal/approval` or `internal/revert`.
