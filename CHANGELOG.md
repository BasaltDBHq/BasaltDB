# Changelog

All notable changes to BasaltDB are recorded in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
