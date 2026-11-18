## What and why

<!-- What this PR changes and why, for a reader who has not seen any earlier discussion. Link the issue it fixes, if there is one: Fixes #123. -->

## How it was tested

<!-- The tests you added or ran, and anything you checked by hand (commands, hosts, Postgres version). -->

## Checklist

- [ ] The title follows Conventional Commits: `type(scope): message`
- [ ] New behaviour has tests; guard and ledger tests run against a real Postgres
- [ ] `make fmt` and `make lint` pass locally; CI runs the full `make ci`
- [ ] A user-facing change has an entry under `## [Unreleased]` in `CHANGELOG.md`
- [ ] `CONTRACT.md` is updated if a surface changed (MCP tools, CLI output, errors, wire formats)
- [ ] Docs are updated if setup, commands or output changed
- [ ] No credentials, connection strings with passwords, or real data in code, tests or this description

Opening this PR means you accept the Contributor Licence Agreement in `CONTRIBUTING.md`.
