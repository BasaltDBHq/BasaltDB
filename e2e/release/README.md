# Release end-to-end test

Walks the built `basalt` binary through the main path of a person-operated
engine: install the engine service, set up on the setup page with a passkey,
the agent's MCP session, a held write's approval, a revert, and removal: the
page's one-press Remove, after which the install's removal job removes the
engine from the computer (macOS keeps the `_basalt` account, Linux deletes
it) and the agent's `status` answers `REMOVED`; then the install again, as a
first install.

```
sh e2e/release/run.sh <bin-dir>     # <bin-dir> holds the basalt binary under test
```

It installs Postgres and the engine as a system service and needs passwordless
`sudo`, Go and Node, so it runs on a CI runner only, never on a developer
machine. Run it from the CI workflow's manual `release-e2e` job
(`gh workflow run ci.yml --ref <branch>`), which runs it on a snapshot build on
macOS (arm64 and Intel) and Ubuntu. The release workflow runs the same script
against the archives it built.

- `run.sh`: leaves the binary where the archive was unpacked, a folder the
  runner's own account owns, as a Homebrew prefix is a person's: the install
  script copies it, root's, to the service's own path, and `flow.mjs` checks
  that copy and its removal. It starts Postgres and seeds `public.items`
  (20 rows), installs the Node dependencies and Chromium, and runs `flow.mjs`.
  It removes the service on exit.
- `flow.mjs`: the steps, each printing `e2e: <step> ok`. The browser is
  Chromium with a virtual authenticator, so the passkey needs no person.
- `mcp.mjs`: a stdio JSON-RPC client for `basalt mcp`.
- `service.sh`: the install and remove scripts that `basalt init` runs through
  the administrator dialog, run under `sudo` instead, and the cleanup that
  collects the engine's logs. `run.sh`'s EXIT trap runs that cleanup, so a
  job needs no separate cleanup step; it only uploads `e2e/release/out` as an
  artifact.
- `installscript/`: prints those scripts from the same code `init` uses.

When a main path changes (install, the setup page, the agent's read and write,
a held write's approval, revert, remove), update the steps in the same change.
