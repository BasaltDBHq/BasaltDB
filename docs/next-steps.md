# When something needs doing: next steps, status and upgrade

Every error and every result the agent has to act on tells it what to do next and what to tell you. This page covers what you will see, how to check your setup yourself, and how to upgrade the guard. The exact wire format and the full list of cases are in [CONTRACT.md, Next steps](../contract/next-steps.md#next-steps), and the catalog is [`api/mcp/errors/next-steps.json`](../api/mcp/errors/next-steps.json).

## What the agent gets

An error or a result that needs action carries:

- **`nextSteps`**, an ordered list. Each step names who acts (`AGENT` or `PERSON`) and what to do. The agent does its own steps in order. A `CALL_TOOL` step comes with its arguments filled in, so the agent does not guess them.
- **`personMessage`**, set whenever you must know or do something. The agent shows it to you word for word. It holds the plain explanation, the command to run or the link to open, and any deadline.

The steps never tell the agent to get around a limit. It does not split a write below the hold threshold to avoid an approval, and it does not retry a refusal in a loop. `STOP` means the agent does not retry or work around the refusal. `END_TURN` means it ends its turn and waits for you. Over 50 rows the agent stops and asks you.

Commands in a `personMessage` are complete and can be pasted: they name `--agent` and the ids, and `--config` when your config is not at the default path. They never contain a secret. A command that needs the admin connection string asks you for it itself.

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
| `GUARD_OUTDATED` | ERROR | The guard is missing a breaking migration. Run `basalt upgrade`. |
| `GUARD_UPGRADE_AVAILABLE` | WARNING | Only non-breaking migrations are missing. Everything works. |
| `NO_PASSKEY` | WARNING | No passkey is registered, so held writes cannot be approved yet. |
| `SETUP_NOT_RUN` | ERROR | A setup code from `basalt init --remote` was never run. |
| `SETUP_EXPIRED` | ERROR | A setup code expired before it was run. |
| `SETUP_CHANGE_PENDING` | WARNING | A setup code that changes the setup is waiting to be run. |

The schema is [`api/mcp/tools/status.json`](../api/mcp/tools/status.json).

## Degraded mode

Two situations leave the agent with `status` and nothing else.

- **The engine is not running.** `basalt mcp` still starts. It serves the tool list and `status`, and answers every other tool `UNAVAILABLE` with reason `ENGINE_UNREACHABLE`. It holds no credential and reaches no database. For an engine that runs as your own OS user (not a service), `basalt mcp` first starts it itself and waits up to 15 seconds, so you see this answer only when that fails: it then names the reason and the engine log, and `status` shows `ENGINE_START_FAILED`. `status` says to start the engine. Once the engine runs, the next call works. You do not need to restart the agent.
- **The guard is behind by a breaking migration.** The engine serves `status`, and every other tool answers `UNAVAILABLE` with reason `GUARD_OUTDATED` and the steps to run `basalt upgrade`. The engine checks the guard's version again on every call. After the upgrade it serves normally, with no restart.

If the guard is behind only by non-breaking migrations, nothing is degraded. `run_start` carries a `GUARD_UPGRADE_AVAILABLE` warning and `status` lists it as a warning. Upgrade when it suits you.

## `basalt status`

`basalt status` shows the same picture without the agent:

```sh
basalt status --agent NAME
```

It prints where the config, sockets and state directory are, whether the engine is running and its build, the pages origin, who operates the engine, the Vault state and engine id (see [vault.md](vault.md)), and then, for the agent, whether the guard is current, whether a passkey is registered, and each problem with the command to fix it. `--json` prints the `status` tool's result plus where the engine runs. Add `--config PATH` for a config that is not at the default path. Without root, when nothing is installed at the default path, `basalt status` (and `basalt log`, `approve`, `revert`, `access`, `upgrade`, `passkey list`, `passkey check`, `basalt mcp` and `basalt engine`) read the per-user `engine.json` that `basalt init --remote` left in your user config directory, so a bot needs no `--config`. For an engine that runs as a service, give `--agent NAME`, because the engine's files belong to its own OS user.

## `basalt upgrade`

`basalt upgrade` installs the missing `basalt_meta` migrations with the admin connection string, and nothing else. It does not rotate the agent's password, change policies, register a passkey or restart the engine.

```sh
basalt upgrade --agent NAME            # shows the SQL, asks, then runs it
basalt upgrade --agent NAME --dry-run  # shows the SQL and runs nothing
basalt upgrade --agent NAME --yes      # does not ask before running the SQL
```

- It first checks the guard with the agent's own credential (through the engine in service mode). If the guard is current it says so and stops. It does not ask for the admin string.
- It asks for the admin connection string at a hidden prompt, uses it once and does not store it. If that string points at a different database than the agent's credential does, it refuses before it connects.
- It runs all the missing migrations in one transaction, so a failure changes nothing.
- It refuses if the guard is newer than this `basalt` build. Install the newer `basalt` instead.
- It refuses if the guard is not installed. Use `basalt init` for that.
- On an engine operated by its agent, it refuses without asking for the admin string, because that string never goes on that machine. Run `basalt init --remote --agent NAME` on the engine's machine, then `basalt init --setup-code <code>` on your own computer.

After it succeeds, the engine serves the agent again without a restart.

## After pulling a new build

Rebuild `basalt`, run `basalt upgrade --agent NAME`, restart the engine, and start a new agent session so it loads the new tool descriptions and instructions. You do not run `basalt init` again to upgrade.

If something fails, read the agent's `personMessage` first, then run `basalt status --agent NAME`.
