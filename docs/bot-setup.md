# Instructions for the bot: set up Basalt for a person who is not at this server

You are an AI agent. A person wants Basalt between you and their Postgres. They cannot log in to this server. Follow these steps in order.

## Rules

- Never ask for the admin connection string or the database password. Never accept one. If the person pastes one, tell them to change the password now. You do not need it.
- Never send the person an install command of your own. Send only the official release link: https://github.com/BasaltDBHq/BasaltDB/releases
- Show the person any `personMessage` word for word. Show every link on its own line, unchanged.
- You never approve a write and you never sign a revert. Only the person's passkey can.

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
- Without root, init keeps the config and the sockets in your own config directory: `engine.json` in `basalt` inside your user config directory (`${XDG_CONFIG_HOME:-$HOME/.config}/basalt/engine.json` on Linux, `$HOME/Library/Application Support/basalt/engine.json` on macOS). Init does not print it. With `--config <dir>/engine.json`, the config goes there and the sockets go in `<dir>/run`. Without `--config`, `basalt status`, `log`, `approve`, `revert`, `access`, `upgrade`, `passkey list`, `passkey check`, `mcp` and `engine` find the per-user config when no system config is installed.
- A URL with a password is refused. Do not work around it.

The command prints a setup code (`basalt-setup.1.…`) and a setup fingerprint. It does not install or start the engine. Add `--json` to get a `personMessage` and `nextSteps`.

If the code already exists and is still valid, the same command prints it again. `--new-code` makes a new one.

## 3. Send it to the person

Send one message with:

1. The setup code, in a code block.
2. The setup fingerprint.
3. The `personMessage` text, or this: "On your own computer, not this server, install basalt from https://github.com/BasaltDBHq/BasaltDB/releases, then run `basalt init --setup-code <code>`. Check that it shows the same fingerprint. Never paste your database password here. Tell me when it says Done."

Then end your turn. The code works for 24 hours and once.

## 4. Start the engine

Start the engine on this server while you wait. The engine runs as you here. Use the config path from step 2:

```sh
basalt engine --config <path to engine.json>
```

Keep it running in the background: install it as a service (below), or use `tmux` or whatever this server uses. Until the person finishes, the engine answers only `status`, and every other tool says `UNAVAILABLE` with reason `SETUP_PENDING`.

### Running the engine as a service

On a Linux or macOS server where you have `sudo`, the engine can run as a system service: it starts at boot, restarts if it stops, and runs as its own OS user (`basalt` on Linux, `_basalt` on macOS), not as you. Then the database credential belongs to that user and is not readable from your account. Use this instead of `basalt engine` in the foreground when the server is yours to keep.

1. Put the release binary where only root can change it, and run that copy. `basalt service install` refuses a binary, or a directory above it, that anyone but root could change. Step 1 of [install.md](install.md) has the two commands.
2. Install the service with the default config path (`/etc/basalt/engine.json` on Linux):

   ```sh
   sudo basalt service install
   ```

   It creates the engine's OS user and directories, writes the service unit and starts it. A service needs the engine config, so the unit starts working once `basalt init --remote` has written it.
3. Make the setup code as root, so the config and the agent's credential file are written for the service (step 2 above, run with `sudo` and without `--config`). The files go to the engine's OS user.
4. Restart the service so it reads the new config: `sudo systemctl restart basalt-engine` on Linux, `sudo launchctl kickstart -k system/dev.basaltdb.engine` on macOS (`sudo basalt service install` run again also restarts it).
5. Check it. Give `--agent NAME` to `basalt status`, because the engine's files belong to its own OS user.

Later runs of step 2's command (a new code, a new `--write`) need `sudo` and the same config, and then the same restart. To remove the service: `sudo basalt service uninstall`. Where the server has no service manager (a container), see "Containers without systemd" in [install.md](install.md).

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

## Where to read more

Error codes and troubleshooting: https://docs.basaltvault.app/llms.txt
