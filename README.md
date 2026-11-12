# BasaltDB

**BasaltDB is the action ledger for AI agents on your database.** It is not a database: your data stays in your own Postgres.

Every action an agent takes is recorded with who did it, why, what it saw and what it changed. That record is what lets BasaltDB preview an action, stop it, ask a person, and undo it.

BasaltDB is an open-source hobby project, built in public. **It is not usable yet.** The repo is at milestone M0 (reset); see [Status](#status).

## Why

People are starting to let agents work on data directly, with no app in between. The app's screens can go; the rules it enforced cannot, so they have to live next to the data.

- **Your data stays in storage you own.** BasaltDB never becomes the place your data lives.
- **People and agents work on the same data.** A person must be able to see what an agent did, stop what is risky, and take back what was wrong.

The common advice is "never connect agents to production". BasaltDB is for the cases where you will anyway: internal tools, back-office data, personal and small-business bots. It is not for time-critical or mission-critical paths.

## What it is, and what it is not

| It is | It is not |
|---|---|
| A guard for a Postgres you already own (Supabase, Neon, RDS, self-hosted) | A database: your data never moves into BasaltDB |
| One Go binary next to your agent, reached over MCP, plus a guard installed in your database | Agent memory, a sync engine or a vector index |
| A record of every agent action, kept so it can be reverted | A general logging, tracing or secret-management product |
| Open source and free | A company |

## How it works

**Edge engine, guard in the database.** The engine runs next to each agent as its MCP server. Enforcement lives inside your Postgres, so it holds whatever path a write takes.

- **Edge engine.** One Go binary per agent machine, running as its own OS user behind a local socket. It parses SQL with `libpg_query`, refuses what is not allowed, records reads, and holds only that agent's scoped credential. The agent's MCP server is a thin shim that holds no secrets.
- **Guard in `basalt_meta`.** Agent roles belong to `basalt_agents` and have no DDL rights. Triggers act only for agent roles: they require an intent, record old and new rows in the same transaction, and count rows per action, cascaded rows included. Writes by people and the app are never blocked.
- **Approvals.** An approval counts only with a valid signature from the person's passkey, checked inside Postgres. Whatever carries the signed approval cannot forge one, and an agent cannot approve its own action.
- **Cleanup.** Everything lives in the `basalt_meta` schema and is removed with `DROP SCHEMA basalt_meta CASCADE`.

### Default policy

| Change | Decision |
|---|---|
| `SELECT` | Allowed, within a row limit and a time limit |
| `INSERT`, `UPDATE` of 1 to 10 rows | Allowed; intent required; old values kept |
| `INSERT`, `UPDATE` of 11 to 50 rows | Held for approval, with a preview of the rows |
| Any `DELETE` | Held for approval up to 50 rows; refused above 50 |
| `CREATE`, `ALTER`, `DROP`, `TRUNCATE` | Refused for agents |
| Multiple statements, data-changing `WITH`, `COPY`, functions outside an allowlist | Refused |

Rows are counted per action, cascaded rows included. Bulk work over 50 rows belongs in a migration or a data pipeline, run by a person.

### Undo

A revert is a new set of changes that restores the old values; it never rewrites history. You can revert one change, one run, or one task across agents. **People win:** a row someone changed after the agent is skipped and reported as a conflict, never overwritten. Only a person can revert, within the 30 days old values are kept.

## What it does not protect against

- A write that is valid SQL, touches one row, and is wrong for the business. It can only be reverted later.
- Data an agent read and leaked, for example through prompt injection. Row limits and per-agent table access reduce it; nothing un-leaks it.
- Actions outside the database taken on bad data: emails sent, payments made.
- An agent holding a person's or the admin's credential, or sudo on the engine's machine.
- Downstream systems that already consumed a change before it was reverted.

## Status

Milestones are gated by evidence, not dates. Progress is tracked in the [roadmap](docs/redesign/plans/2026-11-11-roadmap-m0-m3.md).

| Milestone | Delivers |
|---|---|
| **M0. Reset** (in progress) | This README, Apache-2.0, old code removed, a Postgres spike of the guard |
| M1. Guarded writes | `basalt init`, per-agent role, engine as its own OS user, MCP, SQL parse and classify, intent required, guard triggers, change record, `basalt log` |
| M1.5. Stale writes | Reads recorded by row version, task ids shared across agents, `STALE_READ` refusal |
| M2. Approvals | Default policy, a preview that can never commit, passkey approval checked inside Postgres, notification |
| M3. Revert | Revert by change and by run, preview, people-win conflict checks |
| M4. Show it | The two-minute demo on a real Supabase project; an [install guide](docs/install.md) |

The product definition, decisions and plans live in [docs/redesign](docs/redesign/README.md).

## Development

```bash
make help   # list targets
make ci     # lint, vet and race tests
```

Postgres tests need a real Postgres: set `BASALTDB_TEST_POSTGRES_URL`. See [AGENTS.md](AGENTS.md) for code and review rules and [CONTRIBUTING.md](CONTRIBUTING.md) for how to contribute.

## Licence

BasaltDB is open source under the [Apache License 2.0](LICENSE). The name is covered by [TRADEMARK.md](TRADEMARK.md).
