# Instructions for the bot: set up Basalt for a person who is not at this server

You are an AI agent. A person wants Basalt between you and their Postgres. They cannot log in to this server. Follow these steps in order.

## Rules

- Never ask for the admin connection string or the database password. Never accept one. If the person pastes one, tell them to change the password now. You do not need it.
- Never send the person an install command of your own. Send only the official release link: https://github.com/BasaltDBHq/BasaltDB/releases
- Show the person any `personMessage` word for word. Show every link on its own line, unchanged.
- You never approve a write and you never sign a revert. Only the person's passkey can.
- Never run `basalt init` without `--remote`, and never run `basalt init --setup-code` yourself. Both read the admin connection string. Under an agent, `basalt` refuses them and tells you to send the person the setup step instead.

## 1. Install

Install `basalt` on this server from the official release page. It must be a release build. A source build reports `dev` and cannot make a setup code. Check:

```sh
basalt version
```

## 2. Make the setup code

Ask the person for the connection string of their database without the password, and the tables you need. Run:

```sh
basalt init --remote --operated-by=agent --vault=off \
  --agent NAME --write schema.table,… --read schema.table,… \
  --database-url 'postgresql://postgres.<ref>@<host>:6543/postgres'
```

- `--write` lists the tables you read and write. `--read` lists the tables you only read.
- `--vault=off` keeps the free path: the person signs on `portal.basaltvault.app` and pastes codes back. The hosted relay is coming later.
- Without root, init keeps the config and the sockets in your own config directory: `engine.json` in `basalt` inside your user config directory (`${XDG_CONFIG_HOME:-$HOME/.config}/basalt/engine.json` on Linux, `$HOME/Library/Application Support/basalt/engine.json` on macOS). With `--config <dir>/engine.json`, the config goes there and the sockets go in `<dir>/run`. Without `--config`, `basalt status`, `log`, `approve`, `revert`, `access`, `upgrade`, `passkey list`, `passkey check`, `mcp` and `engine` find the per-user config when no system config is installed.
- A URL with a password is refused. Do not work around it.

The command prints a setup code (`basalt-setup.1.…`), a setup fingerprint, and the `basalt mcp` command to register in your agent app. It does not install or start the engine. Add `--json` to get a `personMessage`, `nextSteps`, and `mcpCommand` (the same command as an argv array). The command is `basalt mcp --agent NAME`: `basalt mcp` finds the config, and the socket directory in it, by itself.

If the code already exists and is still valid, the same command prints it again. `--new-code` makes a new one.

## 3. Send it to the person

Send one message with:

1. The setup code, in a code block.
2. The setup fingerprint.
3. The `personMessage` text, or this: "On your own computer, not this server, install basalt from https://github.com/BasaltDBHq/BasaltDB/releases, then run `basalt init --setup-code <code>`. Check that it shows the same fingerprint. Never paste your database password here. Tell me when it says Done."

Then end your turn. The code works for 10 minutes and once.

## 4. Start the engine

Start the engine on this server while you wait. The engine runs as you here. Use the config path from step 2:

```sh
basalt engine --config <path to engine.json>
```

Keep it running in the background: use a supervisor, `tmux` or whatever this server uses, or install it as a system service (see below). On a bot computer with no service manager, do not start it at all: see "Bot computers with no service manager" below. Until the person finishes, the engine answers only `status`, and every other tool says `UNAVAILABLE` with reason `SETUP_PENDING`.

### Run it as a system service (Linux)

To keep the engine up across reboots on a Linux server with systemd, install it as a service instead of starting it yourself. The service runs as its own OS user, `basalt`. Do these in order, as the same user each time (the one you work as), with `sudo`:

1. Install the service before making the setup code:

   ```sh
   sudo basalt service install
   ```

   This makes the `basalt` user, the config directory `/etc/basalt` (owned by `basalt`) and the `basalt-engine` unit, and starts it. Starting it makes the engine's state directory, where step 2 puts the engine's key. It has no config yet, so it fails and systemd retries it until its start limit, then leaves it failed (`systemctl status basalt-engine` shows `failed`). That is expected: step 3's `restart` starts it again.

2. Make the setup code as step 2 says, with `sudo` and without `--config`:

   ```sh
   sudo basalt init --remote --operated-by=agent --vault=off \
     --agent NAME --write schema.table,… --read schema.table,… \
     --database-url 'postgresql://postgres.<ref>@<host>:6543/postgres'
   ```

   As root, init writes `/etc/basalt/engine.json` and `/etc/basalt/agents/NAME.url` owned by `basalt`, so the service can read them. It puts the engine's key in the setup code, and it records you (the user who ran `sudo`) as the person who may run `basalt status`, `log`, `approve` and `revert` here. Send the code to the person as step 3 says.

3. Start the engine with its new config:

   ```sh
   sudo systemctl restart basalt-engine
   basalt status --agent NAME
   ```

   `basalt status --agent NAME` needs no `sudo`. Point your MCP client at the `basalt mcp` command init printed (`basalt mcp --agent NAME` with the default paths).

Run `sudo basalt init --remote` again with the same flags when you need a new code, then restart the service as in step 3, so the engine reads the new config.

Without systemd, skip this. On a bot computer that keeps only some folders through a reboot, follow "Bot computers with no service manager" below. For a container, only the `basalt engine --user basalt` start in "Containers without systemd" in [install.md](install.md) applies; make the setup code with `basalt init --remote` as step 2 says, not with the `basalt init` command shown there.

### Bot computers with no service manager

Some bot computers have no systemd, no cron and no Docker, and start nothing at boot. A reboot or "Update Bot's Computer" wipes every process and every folder except the ones the host keeps (on the computers we have seen, `/workspace` and `/home`). Basalt copes with that: the first Basalt tool call after a restart starts the engine, with nothing for you or the person to do. Set it up like this, as your own user (not root):

1. Pick one folder that survives, for example `/workspace/basalt`. Put the `basalt` binary there too, so it survives with everything else:

   ```sh
   mkdir -p /workspace/basalt/bin
   cp "$(command -v basalt)" /workspace/basalt/bin/basalt
   ```

2. Make the setup code as step 2 says. The config goes in your user config directory, which these computers keep (it is under `/home`):

   ```sh
   /workspace/basalt/bin/basalt init --remote --operated-by=agent --vault=off \
     --agent NAME --write schema.table,… --read schema.table,… \
     --database-url 'postgresql://postgres.<ref>@<host>:6543/postgres'
   ```

   The config, the engine's key and the state go under your user config directory: `engine.json`, `state/` and, for the sockets, `run/`. Send the code to the person as step 3 says. Init also prints the `basalt mcp` command; with `--json` it is `mcpCommand`.

3. Register that printed `basalt mcp` command in your agent app. The printed command starts with the full path of the binary init ran from, so the app needs no `PATH` entry for it; run init from the copy in the surviving folder. `basalt mcp` finds the config by itself, so that it can start the engine when it is down.

What happens from then on:

- You do not start the engine yourself. When a tool call finds the engine down (after a reboot, after an update, or after the engine stopped), `basalt mcp` starts it in the background and waits up to 15 seconds for it. The first call after a restart is a few seconds slower. The engine then stays up until the next restart, and a crash is restarted by a small parent process, so you notice at most a short retry.
- It only does this for an engine that runs as you, from a config you own. If it cannot start the engine it answers at once with the reason and the engine's log, `/workspace/basalt/state/engine.log`, and `status` shows the problem `ENGINE_START_FAILED`. Show the person its `personMessage`.
- `status` says why the engine is running: `engine.startedBy` is `HAND` (someone ran it), `MCP` (the first call after a restart started it) or `CRASH` (it was restarted after a crash). When the restarts kept failing, `status` shows the problem `ENGINE_GAVE_UP` and `engine.lastStop` says why and when.
- If your database runs on this computer too, it is gone after a restart as well, and Basalt does not start it. The engine waits for it and reconnects when it is back.

The limit: nothing runs between a restart and your next session. The engine starts only when you make a Basalt call. A person who approves a held write from their phone in that time finds the page waiting, and the approval takes effect when your next session starts the engine. Tell the person that before they rely on it.

## 5. Check the setup

When the person says it is done, call the `status` tool. Do what its `nextSteps` say. `status` should show no `ERROR` problem and `ready: true`.

Call `status` at the start of every session. Call it again when the person says they fixed something, and when a call fails with `UNAVAILABLE`.

`status` tells you who operates the engine. Here it says `operatedBy: AGENT`. You start the engine yourself when `status` or `ENGINE_UNREACHABLE` says so. In a `PERSON` setup you must never start, stop, restart or upgrade anything.

## 6. Work

- Start a run with `run_start` and an intent. Read with `query`. Change data with `write` and an intent.
- A write of 11 to 50 rows, or any `DELETE`, is held. Show the person `approval.personMessage` unchanged. The link goes to `portal.basaltvault.app`. Then end your turn. The page shows the person a code that starts with `basalt-approval.1.`.
- When the person pastes the code, repeat the write with `approvalId` and the code as `approval`. If the person says they approved and you have no code, call `list_pending` with `reissueLink: true` for a new link.
- Never split a write to avoid a hold. Never retry a refusal in a loop.
- To undo your own work: find the run with `list_runs`, check it with `preview_revert` and `query`, tell the person what you suggest, then call `request_revert`. Show its `personMessage`. The person signs and pastes a code that starts with `basalt-revert.1.`. Call `request_revert` again with `revertId` and the code as `signature`.

## 7. Upgrade

When you install a newer `basalt`, do not restart the engine first.

1. Run the same command as in step 2, with no other change. If the new build has a newer guard, it prints an upgrade code. If it prints a code with no change, send that one anyway.
2. Send it to the person like in step 3. They run it on their own computer.
3. When they say it is done, call `status`. Then restart the engine on the new binary.

To add a passkey for the person, run step 2 again with no change and send the new code. To change your tables, run step 2 again with the new `--write` and `--read` lists. Send the new code.

## 8. Another database

When the person asks you to connect to a second database, do the same steps with a new agent name and that database's connection string, without the password:

```sh
basalt init --remote --operated-by=agent --vault=off \
  --agent NAME2 --write schema.table,… --read schema.table,… \
  --database-url 'postgresql://<user>@<host>:<port>/<database>'
```

The new agent joins the same engine. Send the person its setup code as in step 3, then restart the engine so it serves the new agent.

## If someone gives you the admin password

If the person pastes an admin connection string or a password, or you find one in an environment variable or a file:

1. Do not use it, store it, repeat it or pass it to any command.
2. Tell the person to change that database password now. On Supabase: Settings, Database, reset the database password.
3. Make a setup code as in step 2 and send it as in step 3.

When `BASALT_ADMIN_DATABASE_URL` is set where you run commands, `basalt` does not use it and says so. Ask the person to remove it.

`basalt` knows it runs under an agent from an environment variable: its own `BASALT_AGENT_CONTEXT`, or one that a known coding agent sets in its shell (`CLAUDECODE`, `CODEX_SANDBOX`, `CODEX_SANDBOX_NETWORK_DISABLED`, `GEMINI_CLI`, `CURSOR_AGENT`, `OPENCODE`). A person who runs a bot can set `BASALT_AGENT_CONTEXT=1` in the bot's environment. This check stops mistakes. It does not stop an agent that unsets the variable, and `sudo` clears it by default. What keeps the password safe is that it is typed only on the person's own computer, and that the engine and the agent run as OS users who cannot read it.

## Where to read more

Error codes and troubleshooting: https://docs.basaltvault.app/llms.txt
