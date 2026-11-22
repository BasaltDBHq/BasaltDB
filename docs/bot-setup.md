# Instructions for the bot: set up BasaltDB for a person who is not at this server

You are an AI agent. A person wants BasaltDB between you and their Postgres. They cannot log in to this server. Follow these steps in order.

## Rules

- Never ask for the admin connection string or the database password. Never accept one. If the person pastes one, tell them to change the password now. You do not need it: they type it on a page.
- Never send the person an install command of your own. Send only the official release link: https://github.com/BasaltDBHq/BasaltDB/releases
- Show the person any `personMessage` word for word. Show every link on its own line, unchanged.
- You never approve a write and you never sign a revert. Only the person's passkey can.
- Run `basalt init --remote` on this server, never plain `basalt init`: the person is not here to answer a dialog or open a local page.
- Never ask the person for the database's address or its tables: the connect page asks for them.

## 1. Install

Install `basalt` on this server from the official release page. It must be a release build. A source build reports `dev` and cannot make a setup link. Check:

```sh
basalt version
```

## 2. Make the setup link

Do not ask the person for anything about the database: not its address, not its tables. Run:

```sh
basalt init --remote --agent NAME
```

- `--agent NAME` is the only flag. Without it, init sets up the one agent the config has, or `demo_bot` on a new engine.
- On a new engine, init marks it agent-operated: the person sets up on `portal.basaltvault.app/connect`. Afterwards the config says so and `--remote` changes nothing.
- Without root, init keeps the config and the sockets in your own config directory: `engine.json` in `basalt` inside your user config directory (`${XDG_CONFIG_HOME:-$HOME/.config}/basalt/engine.json` on Linux, `$HOME/Library/Application Support/basalt/engine.json` on macOS).

The command prints a connect link, a setup fingerprint, a message for the person, and the `basalt mcp` command to register in your agent app. It does not install or start the engine. The command is `basalt mcp --agent NAME`: `basalt mcp` finds the config, and the socket directory in it, by itself.

Every recovery is the same command. If the link is still valid, `basalt init --remote` prints it again. When it expired, when the person said the database is not theirs, or when the engine refused the address the page handed over, the same command makes a new link by itself. There is no flag for that.

## 3. Send it to the person

Show the person the message init printed, word for word, with the link on its own line. The page asks them for their database's connection string; they paste it there, never in the chat. Then end your turn. The link works for 10 minutes and once.

## 4. Start the engine

Register the `basalt mcp` command init printed in your agent app. When a tool call finds the engine down, `basalt mcp` starts it in the background and waits up to 15 seconds for it. You do not start it yourself. Until the person finishes, the engine answers only `status`, and every other tool says `UNAVAILABLE` with reason `SETUP_PENDING`. The engine picks up the database's address from the page by itself; `status` then asks you to confirm the database with the person (`confirm_database`).

`basalt mcp` starts only an engine that runs as you, from a config you own. That is the case here, because init ran as you.

### Bot computers with no service manager

Some bot computers have no systemd, no cron and no Docker, and start nothing at boot. A reboot or "Update Bot's Computer" wipes every process and every folder except the ones the host keeps (on the computers we have seen, `/workspace` and `/home`). BasaltDB copes with that: the first tool call after a restart starts the engine, with nothing for you or the person to do. Set it up like this, as your own user (not root):

1. Pick one folder that survives, for example `/workspace/basalt`. Put the `basalt` binary there too, so it survives with everything else:

   ```sh
   mkdir -p /workspace/basalt/bin
   cp "$(command -v basalt)" /workspace/basalt/bin/basalt
   ```

2. Make the setup link from that copy, as step 2 says:

   ```sh
   /workspace/basalt/bin/basalt init --remote --agent NAME
   ```

   The config, the engine's key and the state go under your user config directory, which these computers keep (it is under `/home`): `engine.json`, `state/` and, for the sockets, `run/`. Send the link to the person as step 3 says.

3. Register the printed `basalt mcp` command in your agent app. It starts with the full path of the binary init ran from, so the app needs no `PATH` entry for it.

What happens from then on:

- When a tool call finds the engine down (after a reboot, after an update, or after the engine stopped), `basalt mcp` starts it and waits up to 15 seconds. The first call after a restart is a few seconds slower. A crash is restarted by a small parent process, so you notice at most a short retry.
- If it cannot start the engine it answers at once with the reason and the engine's log, `/workspace/basalt/state/engine.log`, and `status` shows the problem `ENGINE_START_FAILED`. Show the person its `personMessage`.
- `status` says why the engine is running: `engine.startedBy` is `HAND` (someone ran it), `MCP` (the first call after a restart started it) or `CRASH` (it was restarted after a crash). When the restarts kept failing, `status` shows the problem `ENGINE_GAVE_UP` and `engine.lastStop` says why and when.
- If your database runs on this computer too, it is gone after a restart as well, and BasaltDB does not start it. The engine waits for it and reconnects when it is back.

The limit: nothing runs between a restart and your next session. The engine starts only when you make a tool call. A person who approves a held write from their phone in that time finds the page waiting, and the approval takes effect when your next session starts the engine. Tell the person that before they rely on it.

## 5. Check the setup

When the person says it is done, call the `status` tool. Do what its `nextSteps` say. `status` should show no `ERROR` problem and `ready: true`.

Call `status` at the start of every session. Call it again when the person says they fixed something, and when a call fails with `UNAVAILABLE`.

`status` tells you who operates the engine. Here it says `operatedBy: AGENT`. In a `PERSON` setup you must never start, stop, restart or upgrade anything.

## 6. Work

- Start a run with `run_start` and an intent. Read with `query`. Change data with `write` and an intent.
- A write of 11 to 50 rows, or any `DELETE`, is held. Show the person `approval.personMessage` unchanged. The link goes to `portal.basaltvault.app`. Then, in the same turn, repeat the write once with `approvalId`: it waits for the person's passkey and applies the write. The page sends the signature itself; there is no code to pass on.
- If that wait runs out, end your turn. When the person says they approved, repeat the write with `approvalId`. If they lost the link, call `list_pending` with `reissueLink: true` for a new one.
- Never split a write to avoid a hold. Never retry a refusal in a loop.
- To undo your own work: find the run with `list_runs`, check it with `preview_revert` and `query`, tell the person what you suggest, then call `request_revert`. Show its `personMessage`. Then call `request_revert` once with `revertId`: it waits for the person to sign on the page.

## 7. Upgrade

When you install a newer `basalt`, do not restart the engine first.

1. Run `basalt init --remote --agent NAME` again. If the new build has a newer guard, it prints a link for the upgrade.
2. Send it to the person like in step 3.
3. When they say it is done, call `status`. Then restart the engine on the new binary.

When `status` or an error says the database refuses your credential (`CREDENTIAL_REJECTED`), run the same command: it makes a link that sets a new password.

## 8. Another database

When the person asks you to connect to a second database, do the same steps with a new agent name:

```sh
basalt init --remote --agent NAME2
```

The new agent joins the same engine. Send the person its link as in step 3, then restart the engine so it serves the new agent.

## If someone gives you the admin password

If the person pastes an admin connection string or a password, or you find one in an environment variable or a file:

1. Do not use it, store it, repeat it or pass it to any command.
2. Tell the person to change that database password now. On Supabase: Settings, Database, reset the database password.
3. Make a setup link as in step 2 and send it as in step 3.

Every MCP tool also refuses an argument that holds a `postgres://` URL with a password (`INVALID_ARGUMENT`, reason `ADMIN_CREDENTIAL`). That check stops mistakes. The boundary is that the password is typed only on a page, and that the engine and the agent run as OS users who cannot read each other's files.

## Where to read more

Error codes and troubleshooting: https://docs.basaltvault.app/llms.txt
