# Architecture

A five-minute map of the code for someone new to it. The exact behaviour of every surface is fixed in [CONTRACT.md](../CONTRACT.md); the code and review rules are in [AGENTS.md](../AGENTS.md). This page says where things are.

## One binary, three places it runs

BasaltDB is one Go binary, `basalt` (`cmd/basalt`), plus a schema installed in the person's Postgres. The same binary plays three roles.

- **Setup command.** `basalt init` is what an agent runs to start setup, a guard update, a repair or a removal. It prints one link and the person finishes on a page. These live in `cmd/basalt`.
- **Engine.** `basalt engine` is a long-running service on the agent's machine, running as its own OS user. It serves each agent over a Unix socket, checks the agent's SQL, and holds that agent's scoped Postgres credential. It is the first filter, not the boundary. Code: `internal/app`.
- **MCP shim.** `basalt mcp --agent NAME` is the process an MCP client starts. It only relays stdio to the engine's socket. It holds no credential and parses no SQL. Code: `internal/platform/shim`.

The fourth piece is not Go. The **guard** is the `basalt_meta` schema in the person's Postgres: roles, row triggers, the ledger and the functions that verify approvals. It is what holds whatever path a write takes. Its SQL is in `internal/adapter/outbound/postgres/guard/schema/*.sql`, embedded in the binary and run in name order; `internal/adapter/outbound/postgres/guard` installs it and makes the calls the engine needs inside an agent's transactions.

```
MCP client --stdio--> basalt mcp (shim) --unix socket--> basalt engine --agent credential--> Postgres
                                                                                              basalt_meta (guard)
person --> setup page (admin credential, once) --------> engine or connect service --> Postgres
person --> approval / revert page (passkey) -----------> engine or relay --> basalt_meta checks the signature
```

## How a held write reaches approval, and how it is reverted

1. The agent calls the `write` tool. The engine parses the statement (`internal/core/sqlguard`), refuses what the policy does not allow, and runs the rest on the agent's credential through the guard, inside a transaction that carries the agent's stated intent.
2. The guard's row triggers record old and new rows in the ledger in the same transaction and count rows, cascades included. A write over the row limit, and every `DELETE`, raises an error that the guard turns into a hold instead of a change.
3. The engine previews the rows, stores the hold, and answers `APPROVAL_REQUIRED` with a link. The agent hands the link to the person (`internal/core/links`, `internal/service/agent`).
4. The person opens the page and signs with a passkey. The pages are static files in `web/`, served by the engine on a loopback listener (`internal/adapter/inbound/pages`) or by a hosted portal. The page and whatever carries the signed result are not trusted.
5. Postgres verifies the P-256 signature in `basalt_meta.submit_approval`. Go has a mirror of that check (`internal/core/passkey`) for early feedback, but only Postgres's check counts. `internal/core/approval` encodes the codes that travel between the engine, the page and the relay.
6. The agent repeats the `write` with the approval id, and the engine applies exactly what was previewed. If the rows changed meanwhile, it is refused.

A revert follows the same path with one difference: an agent can only prepare it (`request_revert`), and the person signs. `basalt_meta.apply_revert` verifies the signature and writes a new change that restores the old values. It never edits history, and a row someone changed after the agent is skipped and reported, not overwritten. Code: `internal/core/revert` for the codes, `internal/adapter/outbound/postgres/guard/schema/006_reverts.sql` for the apply.

## Package map

The code layout, the import rules, the core register and the file lists for reverts and approvals are in [ARCHITECTURE.md](../ARCHITECTURE.md). Start with `cmd/basalt/main.go` to see how commands are dispatched, then follow one command into `internal/`.

## Where to start

- **Adding or changing an MCP tool:** the contract first (`api/mcp`, CONTRACT.md), then `internal/service/agent`.
- **Changing what the guard enforces:** a new numbered file in `internal/adapter/outbound/postgres/guard/schema`, never an edit to an applied one.
- **Changing a CLI command:** its file in `cmd/basalt`, and the CLI section of the contract (`contract/cli.md`).
- **Changing what an agent may run:** `internal/core/sqlguard`.
- **Changing a signing page:** `web/`, and the codes in `internal/core/approval` or `internal/core/revert`.
