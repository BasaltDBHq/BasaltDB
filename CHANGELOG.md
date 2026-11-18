# Changelog

All notable changes to BasaltDB are recorded in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking for alpha installs

- Breaking for installs of an alpha release: an agent's `credentialFile` in `engine.json` moves inside `store`. The old key is not read, and every command that loads `engine.json` stops with the edit for the agent. Replace `"credentialFile": "<path>"` with `"store": {"kind": "POSTGRES", "credentialFile": "<path>"}` by hand, then run `basalt upgrade --agent NAME` for the guard schema below.
- The guard's schema moves to version 2, a breaking upgrade: run `basalt upgrade --agent NAME` once after updating the binary. Until then the engine serves only `status`, with the upgrade steps.

### Added

- A daily check for a newer release. After a command, `basalt` prints one line on stderr when a newer release is out, in red when that release has a security fix. It asks the public release list once a day and sends nothing but the request itself. Turn it off with `BASALT_UPDATE_CHECK=off` or `"updateCheck": "OFF"` in `engine.json`. `basalt status --json` carries an `update` field instead of the line, and when the engine runs as a service, `basalt` follows the engine's setting.
- Agents hear about a newer release too: the `status` and `describe` tools carry an `update` message, and the first tool result of each MCP connection repeats it once. The agent is told to pass it on and never to upgrade BasaltDB unless the person says yes.
- `basalt mcp` and the engine agree on a protocol version when they connect. If the two builds do not fit, the agent gets a clear error that says to reconnect the MCP server or restart the engine, instead of a failure that depends on what changed.
- The engine restarts itself onto an upgraded binary installed at the path it was started from, with or without a service manager such as systemd or launchd. It waits for running calls to finish first, then admits nothing new. A request it turns away with error `-32003` was not run, and `basalt mcp` sends it once more to the restarted engine.
- When `basalt` panics, it saves a scrubbed crash report on your machine (version, OS, command, stack; no SQL, table or column names, row values, connection strings, host names, home paths or environment values) and prints one line pointing to `basalt crash show <id>` and `basalt crash report <id>`. `basalt crash list` and `show` let you read exactly what was saved; `report` opens a pre-filled GitHub issue that you review and submit yourself. Nothing is sent by basalt. A tool call in the engine that panics now ends with an `INTERNAL` error instead of stopping the engine.
- `basalt status` without `--agent` lists the engine's agents when there are several: each agent with the name and host of its database, in text and `--json`. `basalt status --agent NAME` also shows the agent's database and host. No user, port, password or connection string is shown. Under an agent (Claude Code, Codex and the others) it does not list other agents; it asks for `--agent NAME` and says the person can run `basalt status` in their own terminal.
- The MCP `describe` overview names the agent's own database by name and host.
- `basalt plugin list | add | enable | disable | trust | remove`, and a `plugins` list in `engine.json`. `add <dir> --agents a,b [--instance NAME]` verifies the plugin's signature and files, installs its own copy, and adds the entry disabled; `enable` turns it on. Both show the hooks, entity types, egress hosts, whether it runs on this machine or on another host, the signer and the agents, with plain-words warnings, and write nothing until you say yes. Under an agent (Claude Code, Codex and the others), or on an engine an agent operates, `add`, `enable`, adding an agent or a new manifest, and `trust` are refused with `PLUGIN_REFUSED` and change nothing; `disable`, `remove` and removing agents still work. Every entry names the agents it serves, and each must be one of the engine's.
- `basalt plugin check <name>` starts an entry from its verified copy, runs `initialize` and `health`, prints the timing and stops it; it needs no database and sends no data. `basalt plugin keygen --out DIR` makes a signing key pair (the private key file is mode 0600 and never printed, and no file is overwritten), and `basalt plugin sign <dir> --key FILE` checks a plugin's manifest and files and signs it, so you can build and trust your own plugin.
- The engine starts and supervises every enabled plugin. At start it verifies each entry's installed copy (again before every restart), starts it, checks its health every 30 seconds, restarts one that fails with a backoff from 1 to 60 seconds, and stops them all within 5 seconds when it stops. A plugin that fails never stops the engine or another plugin. Each local plugin runs in its own process group, in its installed copy, with no environment but its socket path, and its socket lives in a new private directory removed when it stops. An engine run as a service, or as root, does not start local plugins yet. With no plugins enabled nothing changes.
- `status` shows `PLUGIN_UNAVAILABLE` (an enabled plugin for the agent is not ready) and `PLUGIN_NOT_TRUSTED` (the engine refused to start it: its signature, files or permissions failed), each with `basalt plugin check <name>` and `basalt plugin disable <name>` for you to run.
- `basalt engine --plugin-debug` shows local plugins' stderr on the engine's terminal. Without it plugin stderr is discarded, since it may hold data; it is never logged.

### Changed

- Upgrading no longer needs your agent's MCP client restarted: `basalt mcp` waits up to 15 seconds for a restarted engine and sends a read the engine dropped once more. Writes, approvals and reverts are never sent twice.
- When `basalt` runs under an agent (Claude Code, Codex, Gemini CLI, Cursor's agent, OpenCode, or `BASALT_AGENT_CONTEXT` set), every command that needs the database admin connection string refuses before reading it, and tells the agent to make a setup code with `basalt init --remote` or to give the person the command. An admin connection string in `BASALT_ADMIN_DATABASE_URL` there is not used, and `basalt` says to change that password.
- `basalt init --help` shows only the setup-code path when an agent reads it, `basalt --help` ends with the rule for agents, and the MCP instructions tell the agent never to ask for or accept the admin password.
- Every MCP tool refuses a call whose arguments hold a `postgres://` or `postgresql://` URL with a password (`INVALID_ARGUMENT`, reason `ADMIN_CREDENTIAL`), before it reaches Postgres. The value is never recorded or logged, and the next steps tell the agent to ask the person to change that password.
- When `claude` is on your `PATH`, `basalt init` offers `claude mcp add --scope local ...` and says the server is registered for this project directory only. `docs/mcp-clients.md` shows the per-project setup for `.mcp.json`, Codex and OpenCode.
- Release binaries embed `golang.org/x/crypto` v0.59.0, so binary scanners no longer flag GO-2026-5932. BasaltDB never called the package involved.

### Fixed

- `basalt log` and the engine no longer report "ledger chain broken" on a new, untouched ledger after the database was recreated the same way, for example after removing the Postgres container and running the quickstart again. The guard now identifies each install by a random id instead of the schema's oid, which repeats in a cluster made the same way. An old pin is reported as a reinstall with its notice instead.

### Security

- The release `SHA256SUMS` is signed with keyless cosign, and the signature is attached to the release as `SHA256SUMS.sigstore.json`. `SHA256SUMS` now also lists the portal checksum, so one signature covers every file. See [docs/install.md](docs/install.md) to check it with `cosign verify-blob`.

## [0.0.1-alpha.2] - 2026-11-15

### Fixed

- A connection to the vault that BasaltDB ends itself, for example after the link is rotated, ended, or a session times out, now closes with its reason (such as `LINK_REFUSED` or `TIMEOUT`) instead of an abnormal closure without a code. The session always ended; only the reason could be lost.
- A data race in the vault session's idle timeout, seen only with very short idle timeouts (the default is 5 minutes).

### Changed

- Release binaries are built with Go 1.26.11, the toolchain set in `go.mod`, instead of Go 1.26.0.

## [0.0.1-alpha.1] - 2026-11-15

### Fixed

- The release publishes the Homebrew formula. The 0.0.1-alpha release has the binaries but no formula, so `brew install` starts with this version.

## [0.0.1-alpha] - 2026-11-15

The first public alpha, for macOS and Linux (amd64 and arm64). Expect bugs and breaking changes between alpha releases.

### Added

- The engine and its MCP server: an agent reads and writes your Postgres through BasaltDB, with a scoped role and no database URL of its own.
- The guard, installed in your own Postgres by `basalt init`: it records every agent write with the old values, refuses schema changes and writes of more than 50 rows, and holds writes of 11 to 50 rows and every DELETE for your passkey approval.
- Undo for a run, a single change or a task, signed with your passkey. Rows changed after the agent are left as they are and listed.
- The CLI: `init`, `status`, `log`, `revert`, `upgrade`, `uninstall`, `service` and `classify`.
- Setup for an agent on another machine, with a setup code (`basalt init --remote`).

### Changed

- The guard's schema is kept as SQL files under one version, 1 (`internal/guard/schema/`).

### Known limits

- Windows is not built yet.
- See the [limits page](https://docs.basaltvault.app/limits/) for what BasaltDB does not catch.
