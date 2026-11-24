# Changelog

All notable changes to BasaltDB are recorded in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha] - 2026-11-24

The first release of the 0.1 line, for macOS and Linux (amd64 and arm64). Setup moves from the terminal to a page: the agent runs `basalt init` and the person finishes on the page it links. The CLI only starts things. Expect bugs and breaking changes between alpha releases, and read "Breaking for alpha installs" before you upgrade.

### Added

- The local setup page (`/setup/` on `http://localhost:8787`). On your own computer `basalt init` installs the engine service through the system's administrator dialog, one password and nothing typed in the terminal, then prints and opens the setup link. On the page you type the admin connection string, which is used once and never written or logged, pick the tables the agent gets (read and change, or read only; a table without a primary key is read only), label the columns that hold personal data, create a passkey, read the SQL and run the install in one transaction. A service engine with no `engine.json` yet serves only this page and waits.
- The Update check. `basalt init` on a computer already set up opens the page on a check of what needs you: a guard update, a new database certificate, a certificate that does not match the ledger, columns without a label, no passkey, an agent that cannot log in. It says "All good" or fixes each one with the admin connection string, asked once. The passkey list removes a lost device's passkey and adds one on this device.
- Remove BasaltDB on the setup page. It shows what goes (the ledger, the guard, the agents by name; your tables stay) with the SQL, and runs once you type the database's name. On your own computer `basalt init` then removes the engine service through the administrator dialog. The service stays while the engine still serves an agent of another database.
- The connect page (`https://portal.basaltvault.app/connect`), for an agent on a computer you cannot reach. `basalt init --remote` makes a connect-only setup code and prints its link. The code names no database, so you give the agent nothing about it. The page checks that the code matches the one in the chat, takes the passkey step, and asks for the admin connection string, which it sends to the hosted connect service for that one setup and keeps nowhere. It checks that the bot can reach the database, shows it by name with its tables, and lets you untick tables and label personal data.
- The engine collects a connect-only setup's address itself and logs in with the agent's real password only after you confirm the database in the chat, through the new `confirm_database` tool.
- The connect page runs the update for a bot that is already set up (the guard, labels, passkeys, a changed certificate), and has a Remove BasaltDB tab that needs only the admin connection string: no bot and no setup code.
- Both setup pages ask one question after you paste the admin connection string: "Is this your database?", with the database, its host, the user the string signs in as and how its certificate was verified.
- Trust profiles: which root certificates verify a database's certificate, as data. The engine now connects to Supabase and Amazon RDS with full TLS verification (`sslmode=verify-full`, host name checked) from built-in profiles of their roots, and each provider's roots verify only its own hosts. An operator can place a profile file in `trust.d` next to `engine.json`. `status` reports which trust verifies the agent's database and warns `TRUST_ROOT_EXPIRING`, `TRUST_PROFILE_REFUSED` and `CERTIFICATE_NOT_VERIFIED`.
- Pinning on first use. For a database whose certificate no authority on the machine signs (Cloud SQL, DigitalOcean, Aiven, self-signed), confirming "Is this your database?" pins its certificate authority for that host only. From the connect page the engine pins only when its own reading of the chain matches what you trusted. A chain from a public authority is never pinned. The pin is recorded in the ledger, and a pinned host that presents another certificate is refused with `TRUST_ROOT_CHANGED` until you accept it on the Update check.
- `basalt engine --supervise` restarts a crashed engine with a backoff and gives up after five fast crashes in a row, recording why. `basalt mcp` starts a same-user engine it finds down, so a bot's computer that lost its engine after a reboot or an update needs no step. `--started-by` says why an engine started, and `status` reports it.
- The engine restarts itself onto an upgraded binary installed at the path it was started from, with or without a service manager, once running calls finish. `basalt mcp` waits for the restarted engine and sends a dropped read once more; writes, approvals and reverts are never sent twice. `basalt mcp` and the engine agree on a protocol version when they connect.
- A daily check for a newer release. `basalt` prints one line on stderr when one is out, and the agent's `status` and `describe` carry an `update` message for it to pass on. It sends nothing but the request. Turn it off with `BASALT_UPDATE_CHECK=off` or `"updateCheck": "OFF"` in `engine.json`.
- On an engine you operate, `basalt mcp` opens a link to the engine's own local pages in the browser when a result carries one, such as a held write's approval page or a revert to sign. It opens no other URL, and nothing on an engine an agent operates.
- When `basalt` panics it saves a scrubbed crash report on the machine, and `status` names the newest one with a link to file it on GitHub yourself. Nothing is sent. A tool call that panics ends with `INTERNAL` instead of stopping the engine.
- The `status` tool lists the tables the agent can read and write and names each passkey with a check code. `describe` names the agent's database and host.
- The CLI's help and the MCP instructions say that one engine serves many agents, each on one database, and that another database needs another agent.
- The portal has a home page and a not-found page.

### Changed

- Every next step, warning and person message hands the person a link, never a `basalt` command. A setup job is an agent step that runs `basalt init` (`basalt init --remote` on an agent-operated engine), which prints the link.
- Approvals and reverts are signed only on a page with a passkey: the engine's own pages on your computer, or the portal on a bot's computer, whose signature the hosted relay carries to the engine. Nothing is pasted. A whole-task revert is `request_revert` with `taskId`, widened on the signing page, and a revert too large to prepare in one call is split with `runs` or `tables`.
- A portal short link (`/approvals/*`, `/reverts/*`) opens an end-to-end encrypted session to the engine through the BasaltDB Vault relay (`wss://relay.basaltvault.app`). The page shows the engine's fingerprint to compare before you sign, and the engine's receipt for the signature.
- `basalt init --remote` prints the `basalt mcp` line with the absolute path of the running binary, so an agent app whose `PATH` lacks it can still start it. A binary in a temporary folder gets a warning to move it.
- The README, `llms.txt` and `docs/` describe the simplified product. No guide asks a person to type a `basalt` command or to paste an admin connection string into a terminal.
- Release builds are reproducible: the same tagged commit built with the Go toolchain set in `go.mod` gives byte-identical archives, packages and `SHA256SUMS`. [docs/RELEASING.md](docs/RELEASING.md) explains how to check a release.
- Release binaries embed `golang.org/x/crypto` v0.59.0, so binary scanners no longer flag GO-2026-5932. BasaltDB never called the package involved.
- The setup page and the engine refuse more spellings of an admin connection string in a tool call: JSON text with `\u0026` for `&`, a percent-encoded `password` name or scheme, a password with a space, `postgresql+psycopg2://` and a libpq key and value string. The connection string pasted on the local setup page takes only the parameters the engine needs and refuses file-path keys such as `sslrootcert`, so the engine no longer reads files a pasted string names. Error and status messages no longer advise adding `sslrootcert`.
- A database whose host a built-in trust profile knows (Supabase, Amazon RDS) is checked with `sslmode=verify-full` when the admin connection string names no `sslmode`, which Supabase's own copy of the string does not. The confirm step shows "Verified by Supabase" (or Amazon RDS) and the agent's connection string checks the certificate too. An `sslmode` in the string is kept as given. An RDS host in the China or GovCloud regions, whose roots BasaltDB does not carry, needs `sslmode=require` in the string.
- `status` counts only the passkeys registered on the origin the agent's links open, and it is not `ready` until one can sign there. The tools keep working meanwhile.
- A repair keeps the role's grants. `basalt init --remote` no longer saves the agent's tables, prefix or timeout in `engine.json`, and the database's grants are the only record. A role that was dropped, or that holds no table, asks the person to tick tables on the connect page, which shows the ticks from the connect service's answer.
- `preview_revert` says its timeout is the agent's statement timeout, not the 100 seconds of `request_revert`.

### Removed

- The commands `basalt log`, `status`, `access`, `approve`, `revert`, `passkey`, `classify`, `upgrade`, `uninstall`, `tunnel`, `portal verify`, `service uninstall`, `engine list` and `engine revoke`, with their flags. What they did is in the agent's MCP tools and on the pages. The portal check runs in the release workflow.
- Every `basalt init` flag but `--agent`, `--remote` and `--demo`: `--write`, `--read`, `--prefix`, `--statement-timeout`, `--os-user`, `--engine-user`, `--socket-dir`, `--credential-file`, `--config`, `--no-service`, `--rotate-password`, `--skip-passkey`, `--passkey-label`, `--passkey-origin`, `--add-passkey`, `--agent-rls`, `--operated-by`, `--person-uid`, `--vault`, `--database-url`, `--new-code`, `--direct-addr`, `--dev-local-pages`, `--json`, `--yes` and `--dry-run`. Tables, labels and passkeys are set on the page.
- `basalt init --setup-code`, with `--engine-url` and the laptop half of the setup code, and the terminal setup: the admin connection string prompt and the passkey hand-back with its pairing code.
- `basalt mcp --config`, `--socket-dir` and `--socket`, and `basalt engine --user` with the engine's own privilege drop.
- `write`'s `approval` argument and `request_revert`'s `signature`, with the pasted approval and revert codes on every page.
- The direct transport: the engine's direct listener (`directAddr` in `engine.json`), the engine address recorded with its key, and the portal's engine pin pages (`/engines`, `/engines/add`). Portal pages reach the engine through the relay only.
- The person socket, and the `/passkeys/check` and `/passkeys/forget` pages.
- The `remote-init-result` and `portal-verify-result` JSON schemas, and `docs/setup-from-laptop.md`.
- The `DIRECT_NOT_SERVED` problem from `status`, and the last mentions of the direct transport in the tool schemas.
- The environment variables `BASALT_DATABASE_URL`, `BASALT_ADMIN_DATABASE_URL`, `BASALT_CACHE_DIR` and `BASALTDB_ALLOWED_HOSTS`. The engine reads its connection from `engine.json` only, and the update notice keeps its cache in the user cache folder.

### Fixed

- `basalt init` installs the engine service from a Homebrew `basalt`, or one unpacked in a folder of your own, with no manual step. The one password dialog now copies `basalt` into a folder only root can change (`/usr/local/libexec/basalt` on macOS, `/usr/libexec/basalt` on Linux), checked against what `init` read, and the service runs that copy. Before, `init` refused a binary in a folder your account owns and handed the agent two `sudo` commands, which an agent session cannot run. After `brew upgrade`, `basalt init` copies the new `basalt` over the service's copy and restarts the engine in the same single dialog. Removing BasaltDB deletes the copy. No message tells you or the agent to run `sudo`.
- A Vault session that a duplicated or otherwise refused frame ends now always closes with `FRAME_INVALID`. It could close with `PROTOCOL` instead and send the Vault a second `SESSION_CLOSE`.
- The engine no longer reports "ledger chain broken" on a new ledger after the database was recreated the same way, for example after running the quickstart again on a fresh Postgres container. The guard now identifies each install by a random id instead of the schema's oid.
- A program on your computer could finish the first setup with a database it controls and leave you unable to set up your own. Running `basalt init` again now asks "Is this your database?" first. After "No, this isn't mine", `basalt init` asks for your password in the system's administrator dialog and resets BasaltDB on this computer: it deletes the engine's config, credentials and certificate pins, restarts the engine and opens the first-install page. No database is touched. On macOS the dialog says what it asks for.
- The engine opens its agents' sockets before it reads the database, so a slow database no longer makes the engine look down to the bot. The first guard read runs beside the serving and gives up after 15 seconds.
- `basalt init` on a computer with the engine service installed restarts the service, through the administrator dialog, when it runs a different build than the `basalt` you ran, for example after installing a new binary. Before, the old engine kept answering and the fix was not in effect. With no dialog, init stops and names the command to run as root.
- `basalt mcp --agent NAME` and `basalt init --agent NAME` use the engine config that holds the agent when two exist, a service engine's and your own. Before, the MCP server never connected. They stop only when both hold the agent or neither does, and name the agent and both paths.
- A setup that Postgres stops to break a deadlock (`40P01`, most often autovacuum on a table the setup changes) says that a database maintenance task locked a table and that running the setup again is safe. Before, it showed the raw Postgres error.
- Supabase pooler hosts under `.pooler.supabase.co` are recognised as the pooler, like `.pooler.supabase.com`.
- Setup refuses a database with an older or partial BasaltDB install (`GUARD_UNUSABLE`) at the check, before you sign anything, and links [docs/remove-old-install.md](docs/remove-old-install.md). Before, the check passed and the install failed with `SETUP_FAILED`.
- The passkey label defaults to "Passkey on <hostname>" when the setup page sends none, so the install and Add a passkey no longer fail.
- A failed setup run logs its step, its SQLSTATE and the database's reason, with passwords removed.
- Remove on macOS keeps the engine user and its group together, and says so when macOS refuses to delete the user.
- Reinstall repairs a missing engine group and gives root-owned leftover engine folders back to the engine user, so `basalt init` no longer fails with `chown: _basalt: illegal group name` or leaves the engine crash-looping.
- `basalt init` stops and names the log when the engine service keeps crashing, instead of waiting out the 30 seconds.
- `apply_revert_batch` errors for a revert that is not signed yet point at the revert page instead of the removed `basalt revert`.
- The engine's systemd unit now escapes `%` and `$` in the binary and config paths, so a path containing them starts the engine instead of being expanded by systemd.
- Commands the CLI prints now quote an argument that starts with `=`, so a zsh user can paste them: zsh expands `=cmd` to a path.

### Security

- The agent's credential file is read without following a symlink at its path, and a file with a second hard link or owned by another user than the engine's or root is refused. Before, a symlink was followed and only the mode of the file it pointed to was checked. A credential file that is a symlink must be replaced by the file itself.
- An engine started as root on a config outside the service folder reads `engine.json` through the same checked read at every change, not by following a symlink.
- Finishing an install that was interrupted now revokes the agent's grants on tables you did not pick the second time. Before, the agent kept read access to them. On a database where that happened, check the agent role's grants and revoke the ones you did not pick.
- Row-level security covers only the agent's own tables. A setup with no read or no write tables also offered every RLS table the agent's role could already read through another grant, such as one to `PUBLIC`, and a read table could get a write policy. Now only the agent's tables get the agent policy, and read tables get a read-only one. On a database where that happened, drop the agent's policy on each table it was not given: `DROP POLICY <agent role> ON <table>`.
- Setup codes and their links expire 10 minutes after they are made (they lasted 24 hours), and a link is refused on open once used or replaced by a newer code. A link found hours later can no longer walk the setup.
- Every MCP tool refuses a call whose arguments hold a `postgres://` or `postgresql://` URL with a password (`INVALID_ARGUMENT`, reason `ADMIN_CREDENTIAL`), before it reaches Postgres. The value is never recorded or logged.
- The release `SHA256SUMS` is signed with keyless cosign, and the signature is attached as `SHA256SUMS.sigstore.json`. `SHA256SUMS` also lists the portal checksum, so one signature covers every file. See [docs/install.md](docs/install.md) to check it with `cosign verify-blob`.

### Breaking for alpha installs

- An install from an older alpha must be removed first, then set up again: see [docs/remove-old-install.md](docs/remove-old-install.md).
- On the computer that ran a 0.0.1 engine, remove the old engine service and move its config folder (`~/Library/Application Support/basalt/` on macOS, `~/.config/basalt/` on Linux) out of the way before setting up 0.1. Left in place, every command stops with `agent "NAME" is in both engine configs`. The steps are in [docs/remove-old-install.md](docs/remove-old-install.md#upgrading-from-001-clean-up-the-computer).
- `basalt init` on your own computer only starts setup. It installs the engine service through the administrator dialog when needed, prints and opens the setup link, and prints the `basalt mcp` line the agent registers. It never asks for or reads the admin connection string. With no dialog, such as in an SSH session, it stops and never runs the engine as your user instead.
- `basalt init --remote` takes `--agent` and no other flag, and its output is text only. A new engine is agent-operated with the Vault on, and the first run prints the connect link of a connect-only code. An expired or refused setup is forgotten on the next run, which makes a fresh code.
- An agent's `credentialFile` in `engine.json` moves inside `store`. Replace `"credentialFile": "<path>"` with `"store": {"kind": "POSTGRES", "credentialFile": "<path>"}` by hand. An `engine.json` that still has `directAddr` is refused at load: delete the key.
- Every command finds `engine.json` by itself: at the system path, else in your own config directory, and it stops with an error when both exist, unless you name an agent that only one holds. `--config` is a flag of `basalt engine` only, so the MCP line is `basalt mcp --agent NAME`; update the line your MCP client runs. The engine service's unit runs `basalt engine --config <system path> --supervise`.
- The guard's schema moves from version 1 to version 8, and version 2 is breaking. After updating the binary, have the agent run `basalt init` (`basalt init --remote` on a bot's computer) and run the update on the page it links. Until then the engine serves only `status`, with the update link.
- An updated guard refuses a setup code made by an older `basalt`, which carries a 24-hour expiry, with `EXPIRY_TOO_FAR`. Ask the agent for a new link.

### Known limits

- A pin trusts the provider's certificate authority, so where a provider shares one across customers, another customer on the network path could pose as your database.
- A revert that is too large to prepare even when narrowed to one change and one table cannot be reverted through BasaltDB.
- A reboot between Remove on the setup page and its last step leaves the engine service installed until you remove it by hand, as [docs/install.md](docs/install.md) shows.
- Resetting a setup you did not make needs your OS password. A program running as your user can still start a first setup before you do, and you undo it with "No, this isn't mine".
- On Linux, the administrator dialog shows the system's generic text instead of naming what it asks for.

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
