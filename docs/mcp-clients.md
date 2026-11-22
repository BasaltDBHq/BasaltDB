# Connect an agent's MCP client

BasaltDB serves each agent over MCP from the engine, a service running as its own OS user. The agent's MCP client starts `basalt mcp --agent NAME`, a small shim that relays stdio to the engine's socket for that agent. The shim holds no credential; the engine checks that the socket's peer is the agent's OS user (`osUser` in the engine config) and refuses anyone else.

## Before you start

Your agent sets BasaltDB up: it runs `basalt init` and gives you one link, and you finish on a page ([install.md](install.md)). The page ends with the `basalt mcp` line the agent registers in its client. On a person's own computer the engine runs as a service under its own OS user (`_basalt` on macOS, `basalt` on Linux), which the system's administrator dialog creates on the first install. On a bot's computer the engine runs as the bot's own user, and `basalt mcp` starts it ([bot-setup.md](bot-setup.md)).

## Client configuration

Most MCP clients take a command and its arguments. Add one server per agent, run by the agent's OS user (the one the setup page named):

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
- `basalt mcp` finds the engine config by itself (the system path, else the one `basalt init` leaves in your config directory) and reads the socket directory from it. `--agent NAME` is the only flag, and it is needed only when the engine serves more than one agent. When both configs exist, `basalt mcp` stops and names both.
- Do not put a database URL in the client config. The agent never holds one.

The client then lists the agent's tools: `run_start`, `describe`, `query`, `write`, `run_history`, `list_runs`, `list_pending`, `preview_revert`, `request_revert`, `status`, `revert_plan`, `apply_revert_batch`, `confirm_database` and `request_plugin`. A session usually starts a run with an intent, reads with `query` inside that run, and writes with `write` and an intent.

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

The MCP tools `status` and `describe` never name another agent or its database. `describe` names this agent's own database (name and host).

## Check it works

```sh
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"check","version":"0"}}}' \
  | basalt mcp --agent NAME
```

A JSON response naming the server `basalt` means the shim reached the engine. If the connection closes at once, the engine refused the peer: run the command as the agent's OS user, or check `osUser` in the engine config. The engine logs the refusal (`journalctl -u basalt-engine` on Linux, `/Library/Logs/Basalt/engine.log` on macOS).

## Newer releases

The engine looks once a day at the public release list. When a newer release is out, `status` and `describe` carry an `update` field, and the first tool result of each connection carries a line starting `WARNING:` (`SECURITY UPDATE:` for a security release) that the agent relays to you with the upgrade step. The agent never upgrades BasaltDB on its own. Turn the check off with `BASALT_UPDATE_CHECK=off` or `"updateCheck": "OFF"` in `engine.json`.

## Reading the ledger

The agent reads its own change records through MCP: `run_history` for one run, `list_runs` for the runs. You do not read the ledger from a terminal. Ask the agent what it did.

## Approving held writes

A held write comes back to the agent as `APPROVAL_REQUIRED` with `approval.personMessage`, one line for the agent to show you: what is held, and a short link the engine serves (`http://localhost:<port>/approvals/<id>#s=<secret>`; `list_pending` with `reissueLink: true` issues a new one if the agent lost it). On a person's own computer, `basalt mcp` also opens the link in your browser. You approve on that page with your passkey. The agent's repeated `write` with `approvalId` waits up to 90 seconds and returns `APPLIED` once you sign. If that wait runs out, the agent does not wait again: it ends its turn, and applies the write when you tell it you approved. Claude Code moves an MCP call to the background after 2 minutes (`CLAUDE_CODE_MCP_AUTO_BACKGROUND_MS`), so the wait stays under that. A client with a 60 second request timeout should pass a smaller `waitForApproval`. More in [`approving.md`](approving.md).
