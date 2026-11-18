# Changelog

All notable changes to BasaltDB are recorded in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `basalt log` and the engine no longer report "ledger chain broken" on a new, untouched ledger after the database was recreated the same way, for example after removing the Postgres container and running the quickstart again. The guard now identifies each install by a random id instead of the schema's oid, which repeats in a cluster made the same way. An old pin is reported as a reinstall with its notice instead.

### Changed

- Every MCP tool refuses a call whose arguments hold a `postgres://` or `postgresql://` URL with a password (`INVALID_ARGUMENT`, reason `ADMIN_CREDENTIAL`), before it reaches Postgres. The value is never recorded or logged, and the next steps tell the agent to ask the person to change that password.
- Breaking for installs of an alpha release: an agent's `credentialFile` in `engine.json` moves inside `store`. The old key is not read, and every command that loads `engine.json` stops with the edit for the agent. Replace `"credentialFile": "<path>"` with `"store": {"kind": "POSTGRES", "credentialFile": "<path>"}` by hand, then run `basalt upgrade --agent NAME` for the guard schema below.
- The guard's schema moves to version 2, a breaking upgrade: run `basalt upgrade --agent NAME` once after updating the binary. Until then the engine serves only `status`, with the upgrade steps.
- Upgrading no longer needs your agent's MCP client restarted: `basalt mcp` waits up to 15 seconds for a restarted engine and sends a read the engine dropped once more. Writes, approvals and reverts are never sent twice.
- When `basalt` runs under an agent (Claude Code, Codex, Gemini CLI, Cursor's agent, OpenCode, or `BASALT_AGENT_CONTEXT` set), every command that needs the database admin connection string refuses before reading it, and tells the agent to make a setup code with `basalt init --remote` or to give the person the command. An admin connection string in `BASALT_ADMIN_DATABASE_URL` there is not used, and `basalt` says to change that password.
- `basalt init --help` shows only the setup-code path when an agent reads it, `basalt --help` ends with the rule for agents, and the MCP instructions tell the agent never to ask for or accept the admin password.

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
