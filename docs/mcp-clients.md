# Connect an agent's MCP client

BasaltDB serves each agent over MCP from the engine, a service running as its own OS user. The agent's MCP client starts `basalt mcp --agent NAME`, a small shim that relays stdio to the engine's socket for that agent. The shim holds no credential; the engine checks that the socket's peer is the agent's OS user (`osUser` in the engine config) and refuses anyone else.

## Before you start

Run `basalt init --agent NAME --write schema.table,...` with the admin connection string (`BASALT_ADMIN_DATABASE_URL` or the hidden prompt). After the guard and the passkey it asks once:

```
Install the engine as a background service? This creates the OS user _basalt and asks for your password twice: in the system's administrator dialog, then in this terminal. [Y/n]
```

- **Yes** (the default): on a first install, init first asks for your password in the system's administrator dialog (macOS's own, or `pkexec` on Linux), which runs a fixed script: it creates the engine's OS user and the system folders, and installs and starts the unit that runs `basalt engine --config <system path> --supervise`. With no dialog (an SSH session, a machine without a desktop) init stops before it reaches the database, and never runs the engine as you instead. Then init runs one `sudo basalt service install ... --agent NAME --credential-stdin`, which creates the engine's OS user (`basalt` on Linux, `_basalt` on macOS), writes the engine config and the agent's credential into the service's own directories (`/etc/basalt` with state in `/var/lib/basalt` and sockets in `/run/basalt` on Linux; `/Library/Application Support/Basalt` on macOS), owned by that user with mode 0600, and installs and starts the systemd unit or launchd daemon (or restarts it when it is already installed). The credential goes to sudo on stdin, never on a command line. Init then checks that the engine answers on the agent's socket and prints the MCP command. The agent's OS user cannot read the credential.
- **No**, or `--no-service`: init writes the config and credential under your config directory (`~/.config/basalt` on Linux, `~/Library/Application Support/basalt` on macOS) and prints the one command that runs the engine in the foreground as you. Giving `--config`, `--socket-dir` or `--credential-file` also means you run the engine yourself. That is same-user mode: writes are still guarded in Postgres, but the agent's OS user can read its credential file.
- **No terminal** (answers piped in) and neither `--yes` nor `--no-service`: init stops before writing anything and asks you to pass one of them. It never picks same-user mode for you.

`--dry-run` prints the SQL and the exact service steps without running anything. If the `claude` CLI is on your `PATH`, init also offers to run `claude mcp add --scope local basalt-NAME -- basalt mcp --agent NAME` for you (with the full path of the running binary in place of `basalt`); it never runs it without a yes. `--scope local` registers the server for the current project directory only, and init says so.

## Client configuration

Most MCP clients take a command and its arguments. Add one server per agent, run by the agent's OS user (the `--os-user` you gave `init`, yourself by default):

```json
{
  "mcpServers": {
    "basalt": {
      "command": "basalt",
      "args": ["mcp", "--agent", "NAME"]
    }
  }
}
```

- Use the absolute path of `basalt` (`which basalt`) if the client does not inherit your `PATH`.
- If `init` used a non-default `--socket-dir`, add `"--socket-dir", "DIR"` to `args`, or pass the socket directly with `"--socket", "DIR/NAME.sock"`.
- Do not put a database URL in the client config. The agent never holds one.

The client then lists twelve tools: `run_start`, `describe`, `query`, `write`, `run_history`, `list_runs`, `list_pending`, `preview_revert`, `request_revert`, `status`, `revert_plan` and `apply_revert_batch`. A session usually starts a run with an intent, reads with `query` inside that run, and writes with `write` and an intent.

## One project, one database

One MCP server serves one agent, and one agent uses one database. No server routes between databases, so the registration decides which database a session reaches. To give a project its database, register that project's agent in that project only. Do the same again with another agent name in another project; sessions in each project then reach only their own database.

- **Claude Code.** In the project directory: `claude mcp add --scope local basalt-NAME -- basalt mcp --agent NAME`. `local` is private to you and this directory. To share it with the team through the repository, use `--scope project`, which writes `.mcp.json` (below); never `--scope user`, which every project would see.
- **`.mcp.json`** in the project root (Claude Code and other clients that read it):

  ```json
  {
    "mcpServers": {
      "basalt-NAME": { "command": "basalt", "args": ["mcp", "--agent", "NAME"] }
    }
  }
  ```

- **Codex.** In the project's `.codex/config.toml` (Codex reads it only for a project you have trusted) (or `~/.codex/config.toml` for every project, which you should not do for a per-project database):

  ```toml
  [mcp_servers.basalt-NAME]
  command = "basalt"
  args = ["mcp", "--agent", "NAME"]
  ```

- **OpenCode.** In the project's `opencode.json`:

  ```json
  {
    "mcp": {
      "basalt-NAME": { "type": "local", "command": ["basalt", "mcp", "--agent", "NAME"] }
    }
  }
  ```

When the engine's config is not where `basalt mcp` looks by itself (the system path, or the per-user one `basalt init` leaves in your config directory), the line `basalt init` prints carries `--config <absolute path>`, and `--socket-dir` when the sockets are not in the default place. Keep them when you register the server: with the config, `basalt mcp` can answer `status` and, for an engine that runs as you, start it when it is down. [Bot computers with no service manager](bot-setup.md#bot-computers-with-no-service-manager) shows a full line.

The MCP tools `status` and `describe` never name another agent or its database. `describe` names this agent's own database (name and host). To see every agent and its database, run `basalt status` in your own terminal.

## Check it works

```sh
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"check","version":"0"}}}' \
  | basalt mcp --agent NAME
```

A JSON response naming the server `basalt` means the shim reached the engine. If the connection closes at once, the engine refused the peer: run the command as the agent's OS user, or check `osUser` in the engine config. The engine logs the refusal (`journalctl -u basalt-engine` on Linux, `/Library/Logs/Basalt/engine.log` on macOS).

## Newer releases

The engine looks once a day at the public release list. When a newer release is out, `status` and `describe` carry an `update` field, and the first tool result of each connection carries a line starting `WARNING:` (`SECURITY UPDATE:` for a security release) that the agent relays to you with the upgrade step. The agent never upgrades BasaltDB on its own. Turn the check off with `BASALT_UPDATE_CHECK=off` or `"updateCheck": "OFF"` in `engine.json`.

## Reading the ledger

`basalt log --agent NAME` reads the agent's change records with the agent's own credential. Run it as yourself. When the engine runs as a service, its credential file belongs to the engine's user, so `basalt log`, `approve` and `revert` ask the running engine over its person socket instead of reading the file ([install.md](install.md), step 6). In same-user mode (`--no-service`) they read the credential file directly.

## Approving held writes

A held write comes back to the agent as `APPROVAL_REQUIRED` with `approval.personMessage`, one line for the agent to show you: what is held, a short link the engine serves (`http://localhost:<port>/approvals/<id>#s=<secret>`; `list_pending` with `reissueLink: true` issues a new one if the agent lost it), and the equivalent `basalt approve --open` command. You approve on that page with your passkey. The agent's repeated `write` with `approvalId` waits up to 90 seconds and returns `APPLIED` once you sign. If that wait runs out, the agent does not wait again: it ends its turn, and applies the write when you tell it you approved. Claude Code moves an MCP call to the background after 2 minutes (`CLAUDE_CODE_MCP_AUTO_BACKGROUND_MS`), so the wait stays under that. A client with a 60 second request timeout should pass a smaller `waitForApproval`. Authenticators on Linux and approving for an engine on a headless server: [`approving.md`](approving.md).
