# When something needs doing: next steps, status and upgrade

Every error and every result the agent has to act on tells it what to do next and what to tell you. This page covers what you will see, how to check your setup yourself, and how to upgrade the guard. The exact wire format and the full list of cases are in [CONTRACT.md, Next steps](../contract/next-steps.md#next-steps), and the catalog is [`api/mcp/errors/next-steps.json`](../api/mcp/errors/next-steps.json).

## What the agent gets

An error or a result that needs action carries:

- **`nextSteps`**, an ordered list. Each step names who acts (`AGENT` or `PERSON`) and what to do. The agent does its own steps in order. A `CALL_TOOL` step comes with its arguments filled in, so the agent does not guess them.
- **`personMessage`**, set whenever you must know or do something. The agent shows it to you word for word. It holds the plain explanation, the link to open, and any deadline.

The steps never tell the agent to get around a limit. It does not split a write below the hold threshold to avoid an approval, and it does not retry a refusal in a loop. `STOP` means the agent does not retry or work around the refusal. `END_TURN` means it ends its turn and waits for you. Over 50 rows the agent stops and asks you.

A step for you is a link to a page, never a command to type. Nothing in a `personMessage` is a secret, and no page link carries one in a place a server sees (the secret sits after the `#`).

When the engine is person-operated, which is the default, the agent never starts, stops, restarts or upgrades anything on the engine's machine. Those steps are addressed to you.

## The agent checks `status`

The agent calls the `status` tool at the start of a session, after you say you fixed something, and when a call fails with `UNAVAILABLE`. It answers even when the engine is down. The result has `ready`, and a list of `problems`, each with a `severity` (`ERROR` or `WARNING`), a `personMessage` and its own `nextSteps`. `ready` is false when any problem is an `ERROR`.

| Problem | Severity | What it means |
|---|---|---|
| `ENGINE_UNREACHABLE` | ERROR | The agent's MCP command cannot reach the engine. Start it. |
| `DATABASE_UNREACHABLE` | ERROR | The engine cannot reach the database. |
| `TOO_MANY_CONNECTIONS` | ERROR | The agent has used all 8 database connections Basalt allows it. Another engine for the same agent may be running, or a stopped engine left sessions open. Stop any second engine; stale sessions close on their own within a few minutes. See [Connections](install.md#connections). |
| `CREDENTIAL_REJECTED` | ERROR | Postgres refuses the agent's login. |
| `GUARD_MISSING` | ERROR | The guard is not installed. Run `basalt init`. |
| `GUARD_OUTDATED` | ERROR | The guard is missing a breaking migration. The agent runs `basalt init` and gives you the update link. |
| `GUARD_UPGRADE_AVAILABLE` | WARNING | Only non-breaking migrations are missing. Everything works. |
| `NO_PASSKEY` | WARNING | No passkey is registered, so held writes cannot be approved yet. |
| `SETUP_NOT_RUN` | ERROR | A setup code from `basalt init --remote` was never run. |
| `SETUP_EXPIRED` | ERROR | A setup code expired before it was run. |
| `SETUP_CHANGE_PENDING` | WARNING | A setup code that changes the setup is waiting to be run. |

The schema is [`api/mcp/tools/status.json`](../api/mcp/tools/status.json).

## Degraded mode

Two situations leave the agent with `status` and nothing else.

- **The engine is not running.** `basalt mcp` still starts. It serves the tool list and `status`, and answers every other tool `UNAVAILABLE` with reason `ENGINE_UNREACHABLE`. It holds no credential and reaches no database. For an engine that runs as your own OS user (not a service), `basalt mcp` first starts it itself and waits up to 15 seconds, so you see this answer only when that fails: it then names the reason and the engine log, and `status` shows `ENGINE_START_FAILED`. `status` says to start the engine. Once the engine runs, the next call works. You do not need to restart the agent.
- **The guard is behind by a breaking migration.** The engine serves `status`, and every other tool answers `UNAVAILABLE` with reason `GUARD_OUTDATED` and the steps to update it from the setup page. The engine checks the guard's version again on every call. After the upgrade it serves normally, with no restart.

If the guard is behind only by non-breaking migrations, nothing is degraded. `run_start` carries a `GUARD_UPGRADE_AVAILABLE` warning and `status` lists it as a warning. Upgrade when it suits you.

## Checking by hand

You read the setup through the agent: ask it to call `status`. The result says where the engine runs, whether it is reachable and its build, who operates it, the Vault state and engine id (see [vault.md](vault.md)), and, for the agent, whether the guard is current, whether a passkey is registered, and each problem with its next step. The agent's `status` names only its own database. There is no `basalt status` command.

## Updating the guard

When the guard is older than the engine, the agent's `status` says so and the agent gives you a link to the engine's setup page. The update installs the missing `basalt_meta` migrations, and nothing else. It does not rotate the agent's password, change policies, register a passkey or restart the engine.

- The page shows the SQL first. You type the admin connection string there; the engine uses it once and does not store it. If that string points at a different database than the agent's credential does, the page refuses before it connects.
- It runs all the missing migrations in one transaction, so a failure changes nothing.
- It refuses if the guard is current, if the guard is newer than this `basalt` build (install the newer `basalt` instead), or if the guard is not installed.

After it succeeds, the engine serves the agent again without a restart.

## After pulling a new build

Rebuild `basalt`, update the guard from the setup page when `status` asks for it, restart the engine, and start a new agent session so it loads the new tool descriptions and instructions. You do not run `basalt init` again to upgrade the binary. A guard update goes through the setup page, as above.

If something fails, read the agent's `personMessage` first, then ask the agent to call `status`.
