<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/basalt-db-lockup-dark.svg">
    <img src="docs/assets/basalt-db-lockup.svg" alt="BasaltDB" width="300">
  </picture>
</p>

# BasaltDB

**Make agent mistakes reversible.** BasaltDB is the action ledger for AI agents on your database. It is not a database: your data stays in your own Postgres.

Every action an agent takes is recorded with who did it, why, what it saw and what it changed. That record is what lets a person preview an action, stop it and undo it.

> **Status: early.** BasaltDB works end to end on Postgres. This is an alpha prerelease: expect breaking changes. See [Status](#status).

- **Docs:** https://docs.basaltvault.app
- **Install guide:** [docs/install.md](docs/install.md), from nothing to an agent's first guarded write
- **Crash reports:** [docs/crash-reports.md](docs/crash-reports.md), what basalt saves when it crashes and how you file it (nothing is sent for you)
- **Contract:** [CONTRACT.md](CONTRACT.md) and [`contract/`](contract/), the MCP tools, the CLI, the pages and the `basalt_meta` schema

## Why

People are starting to let agents work on data directly, with no app in between. The app's screens can go. The rules it enforced cannot, so they have to live next to the data.

- **Your data stays in storage you own.** BasaltDB never becomes the place your data lives.
- **People and agents work on the same data.** A person must be able to see what an agent did, stop what is risky, and take back what was wrong.

The common advice is "never connect agents to production". BasaltDB is for the cases where you will anyway: internal tools, back-office data, personal and small-business bots. It is not for time-critical or mission-critical paths.

## What it is, and what it is not

| It is | It is not |
|---|---|
| A guard for a Postgres you already own (Supabase, RDS, self-hosted) | A database: your data never moves into BasaltDB |
| One Go binary next to your agent, reached over MCP, plus a guard installed in your database | Agent memory, a sync engine or a vector index |
| A record of every agent action, kept so it can be reverted | A general logging, tracing or secret-management product |
| Open source under Apache-2.0, and complete on its own | A hosted service: the engine runs on your machine and the guard in your database |

## Quickstart

You need macOS or Linux, a Postgres you own, a browser with a passkey, and an MCP client. The [install guide](docs/install.md) has every prompt and every error; this is the short version.

**1. Install `basalt`.**

```sh
brew install basaltdbhq/tap/basaltdb
basalt version
```

To install from a GitHub release, check the archive against `SHA256SUMS` and put `basalt` on your `PATH`. To build from source, see the [install guide](docs/install.md).

**2. Install the guard on a sample schema.** Skip this if you guard your own tables; the [install guide](docs/install.md) shows `--write` and `--read`.

```sh
basalt init --demo
```

Init asks for your admin connection string once and never stores it. It creates a schema `basalt_demo` with 30 leads and 20 notes, prints a short summary of the setup SQL before running it (the full SQL with `--show-sql`), registers your passkey, and starts the engine as a background service. The agent is `demo_bot`.

**3. Connect your agent.** Any MCP client takes the same command:

```json
{
  "mcpServers": {
    "basalt-demo_bot": {
      "command": "basalt",
      "args": ["mcp", "--agent", "demo_bot"]
    }
  }
}
```

Use the absolute path of `basalt` (`which basalt`) if the client does not inherit your `PATH`.

**4. See what it did, and take it back.** `RUN_ID` is the UUID the agent returned from `run_start`.

```sh
basalt log --agent demo_bot --run RUN_ID
basalt revert --agent demo_bot --run RUN_ID
```

`revert` prints a link to a page that shows the rows. Nothing is restored until you sign there with your passkey.

To remove everything, run `basalt uninstall` and then `basalt service uninstall`. Uninstall drops the `basalt_meta` schema, the guard's triggers and policies, the `basalt_*` roles, and the demo schema when `init --demo` created it. Service uninstall stops and removes the engine service.

## How it works

**The engine runs next to the agent. The guard runs inside your database.** Enforcement lives in Postgres, so it holds whatever path a write takes.

- **Engine.** One Go binary per agent machine, running as its own OS user behind a local socket. It parses SQL with `libpg_query`, refuses what is not allowed, records reads, and holds only that agent's scoped credential. The agent's MCP server is a thin shim that holds no secrets.
- **Guard in `basalt_meta`.** Agent roles have no DDL rights. Triggers act only for agent roles: they require an intent, record old and new rows in the same transaction, and count rows per action, cascaded rows included. Writes by people and by your app are never blocked.
- **Signatures.** A held write or a revert counts only with a valid signature from a person's passkey, checked inside Postgres. Whatever carries the signed request cannot forge one, and an agent cannot sign for itself.

### Default policy

| Change | Decision |
|---|---|
| `SELECT` | Allowed, within a row limit and a time limit |
| `INSERT`, `UPDATE` of 1 to 10 rows | Allowed; intent required; old values kept |
| `INSERT`, `UPDATE` of 11 to 50 rows | Held for a person, with a preview of the rows |
| Any `DELETE` | Held for a person up to 50 rows; refused above 50 |
| `CREATE`, `ALTER`, `DROP`, `TRUNCATE` | Refused for agents |
| Multiple statements, data-changing `WITH`, `COPY`, functions outside an allowlist | Refused |

Rows are counted per action, cascaded rows included. Bulk work over 50 rows belongs in a migration or a data pipeline, run by a person.

### Undo

A revert is a new set of changes that restores the old values. It never rewrites history. You can revert one change, one run, or one task across agents.

**People win.** A row someone changed after the agent is skipped and reported as a conflict, never overwritten. So a revert does not promise to restore every row: it restores the ones nobody has touched since.

Old values are kept for 30 days. After that a row can no longer be reverted.

## What it does not protect against

- A write that is valid SQL, touches one row, and is wrong for the business. It can only be reverted later.
- Data an agent read and leaked, for example through prompt injection. Row limits and per-agent table access limit the damage and leave a trail. Nothing un-leaks it.
- Actions outside the database taken on bad data: emails sent, payments made.
- An agent holding a person's or the admin's credential, or `sudo` on the engine's machine.
- Downstream systems that already consumed a change before it was reverted.

## Works with

- **Postgres:** Supabase, RDS, and any Postgres you run yourself and can log in to as an admin.
- **Agents:** any MCP client. The docs cover OpenCode, Claude Code and Codex; [docs/mcp-clients.md](docs/mcp-clients.md) has the configuration for others.

## Status

What works today:

- Guarded writes with a stated intent, a per-agent Postgres role, and the engine as its own OS user
- A record of every read and write, and `basalt log` to read it
- Refusal of a write based on a row that changed after the agent read it
- Holds for larger writes and every `DELETE`, signed with a passkey and checked inside Postgres
- Revert by change, by run and by task, with a preview and conflict checks
- `basalt status`, `basalt upgrade`, `basalt access`, `basalt classify` and `basalt uninstall`, and the MCP `describe` tool

Not there yet:

- Setup from a browser alone, for a person without a terminal.

## Development

```sh
make help   # list targets
make ci     # lint, vet and race tests
```

Postgres tests need a real Postgres: set `BASALTDB_TEST_POSTGRES_URL`. [docs/architecture.md](docs/architecture.md) is a short map of the code. See [AGENTS.md](AGENTS.md) for code and review rules, [CONTRIBUTING.md](CONTRIBUTING.md) for how to contribute, and [SECURITY.md](SECURITY.md) for how to report a vulnerability.

Questions, ideas and setups you want to show go to [Discussions](https://github.com/BasaltDBHq/BasaltDB/discussions). Issues are for bugs and planned work.

## Licence

BasaltDB is open source under the [Apache License 2.0](LICENSE). The name is covered by [TRADEMARK.md](TRADEMARK.md).
