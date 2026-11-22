# Install guide

From nothing to your agent's first guarded write. It works with Supabase and with any plain Postgres you can log in to as an admin (RDS, self-hosted).

The agent runs `basalt`, and you finish on a page. After the install in step 1 you type no `basalt` command: the agent runs `basalt init`, the MCP client runs `basalt mcp`, and the engine runs itself. The one secret, your database's admin connection string, is typed only on a setup page. It never reaches the agent: not in the chat, a file, the environment or a log.

You need:

- macOS or Linux, with a desktop session. The first install asks for your administrator password in the system's own dialog (`osascript` on macOS, `pkexec` on Linux). With no dialog, such as an SSH session or a headless machine, `basalt init` says so and stops. For a bot on a machine you cannot reach, read [bot-setup.md](bot-setup.md) instead.
- A Postgres you own, and its admin connection string, the one for the `postgres` user.
- A browser on the same machine, with a passkey (your laptop's own, a security key, or your phone through the browser).
- An MCP client. [`mcp-clients.md`](mcp-clients.md) has the configuration for Claude Code, Codex, OpenCode and others.

## 1. Install `basalt`

This is an alpha prerelease. Expect breaking changes.

### Homebrew

```sh
brew install basaltdbhq/tap/basaltdb
```

### Release archive

Download an archive from [GitHub Releases](https://github.com/BasaltDBHq/BasaltDB/releases), together with `SHA256SUMS`. Check the archive against `SHA256SUMS`, unpack it, and put `basalt` on your `PATH`.

```sh
curl -fsSL -O https://github.com/BasaltDBHq/BasaltDB/releases/download/v0.0.1-alpha.2/basaltdb_0.0.1-alpha.2_linux_amd64.tar.gz
curl -fsSL -O https://github.com/BasaltDBHq/BasaltDB/releases/download/v0.0.1-alpha.2/SHA256SUMS
grep 'basaltdb_0.0.1-alpha.2_linux_amd64.tar.gz$' SHA256SUMS | sha256sum -c -
tar -xzf basaltdb_0.0.1-alpha.2_linux_amd64.tar.gz
```

#### Check the signature

Releases after `v0.0.1-alpha.2` also carry `SHA256SUMS.sigstore.json`, a [Sigstore](https://www.sigstore.dev/) signature of `SHA256SUMS`. The release workflow signs it with no long-lived key: [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) gets a short-lived certificate for the workflow's GitHub identity, and the signature is recorded in the public Rekor transparency log. A valid signature proves that `SHA256SUMS` came from this repository's release workflow, run for that tag. Since `SHA256SUMS` lists every archive, package and `portal.sha256`, checking the archive against it (above) then covers the archive too.

With `cosign` 2.4 or later installed (the bundle is in the Sigstore bundle format), check the signature before you check the archive:

```sh
TAG=v0.0.1-alpha.3   # the release you downloaded
curl -fsSL -O "https://github.com/BasaltDBHq/BasaltDB/releases/download/$TAG/SHA256SUMS"
curl -fsSL -O "https://github.com/BasaltDBHq/BasaltDB/releases/download/$TAG/SHA256SUMS.sigstore.json"
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/BasaltDBHq/BasaltDB/.github/workflows/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

It prints `Verified OK`. Anything else means the file was not signed by that workflow for that tag: do not use the download.

### Build from source

You need Go 1.26 or newer, and `git`. Then put `basalt` on your `PATH`.

```sh
git clone https://github.com/BasaltDBHq/BasaltDB.git
cd BasaltDB
go build -o basalt ./cmd/basalt
```

Check the install:

```sh
basalt version
```

## 2. Get the connection string

**Supabase.** In the dashboard press **Connect** and copy the string that matches your network:

| String | Use it |
|---|---|
| Session pooler, port 5432 (`postgres.<ref>@aws-0-<region>.pooler.supabase.com`) | If unsure. Works on IPv4 and IPv6. |
| Direct connection (`db.<ref>.supabase.co`) | Only if your network has IPv6. |

Fill in `[PASSWORD]` with your database password, URL-encoding characters such as `@`, `/`, `:` and `#`. Add `?sslmode=require` at the end.

**Plain Postgres.** `postgresql://postgres:PASSWORD@HOST:5432/DBNAME?sslmode=require`

Keep it to paste on the setup page. Never paste it to the agent. If you do, change that database password now.

### Databases signed by their own CA

`basalt` checks the database's certificate whenever it can. Supabase and Amazon RDS sign with their own roots, which it carries, so those hosts verify with no extra step. Google Cloud SQL, DigitalOcean, Aiven and self-signed databases use a CA per instance or project. The setup page does not cover them yet. Until it does, `basalt trust add` and `basalt trust pin` still exist on the engine's machine: `trust pin` reads the CA from the server and asks you to confirm its SHA-256 against your provider's console, as SSH does on first use.

### Connections

### Connections

Each agent's engine opens up to 4 connections to the database, plus 1 while the `status` tool runs. Postgres caps each agent role at 8 connections (`CONNECTION LIMIT 8`).

Budget for it. The number of agents times 8 must fit next to your app's own connections, within the limit your database allows in total.

**On Supabase.** The smallest instance allows roughly 60 direct connections in total. The session pooler (port 5432 on the pooler host, the string recommended above) gives each client connection its own server connection from a shared pool. Count every engine connection against that pool. Transaction mode (port 6543) would share server connections, but it is not yet verified with Basalt. Do not rely on it.

If it does not fit, run fewer agents per database or move to a bigger instance.

When an agent hits its cap, its `status` tool reports `TOO_MANY_CONNECTIONS` with this message:

> The agent <name> has used all 8 database connections Basalt allows it. Another engine for the same agent may be running, or a stopped engine left sessions open. Stop any second engine; stale sessions close on their own within a few minutes.

## 3. Set up with the sample database

Ask your agent to set up BasaltDB with the sample database. The agent runs:

```sh
basalt init --demo
```

1. **The administrator dialog.** On a first install your system asks for your password, once. It runs a fixed script that creates the engine's OS user (`_basalt` on macOS, `basalt` on Linux), the system folders and the service, and starts it. Nothing the agent typed reaches that script. The binary must be one only root can change: put it in a root-owned folder such as `/usr/local/bin`, or install it with Homebrew.
2. **The link.** `basalt init` prints one link, `http://localhost:8787/setup/#...`, and opens it in your browser. The agent shows it to you too, in case the browser did not open. Port 8787 must be free: `lsof -nP -iTCP:8787 -sTCP:LISTEN` shows what holds it.
3. **The page.** It shows the job, the agent's name and the OS user the agent runs as. Check that user. Then type the admin connection string, press **Check**, read what it will do and the SQL, and press **Set up**. When the database has no passkey for this page, the browser asks you to register one first.
4. **Done.** The page says what it did, for example `demo ready: leads 30, lead_notes 20`, and shows the `basalt mcp` line and your passkey's check code. The agent's `status` names the same code.

The setup creates the schema `basalt_demo` with `leads` (30 rows) and `lead_notes` (20 rows), the agent `demo_bot` with write access to those two tables and nothing else, the `basalt_meta` guard schema and the `basalt_*` roles. The SQL runs in one transaction. Running it again keeps the demo rows and the agent's password.

**Your own tables.** The setup page installs the sample database today. Picking your own tables on it is not built yet, so a real database goes through a bot's connect page ([bot-setup.md](bot-setup.md)) for now.

**The limit of this setup.** An agent that runs as your own OS user can serve a lookalike `localhost` page that asks for the admin string, or replace a `basalt` binary in a folder you can write to. A terminal prompt had the same exposure, and BasaltDB does not build around it. Signing stays safe: Postgres checks the exact origin, port included. Look at the address bar and at the OS user the page names before you type the admin string.

Check the engine:

```sh
curl -s http://localhost:8787/healthz
```

It prints `ok`.

### Engine memory

The engine keeps its PII dictionary within `pii.maxMemoryMB` in `engine.json` (default 512). It sets the Go memory limit (`GOMEMLIMIT`) to twice that unless you set `GOMEMLIMIT` yourself. The service's unit carries limits of its own: on Linux, systemd `MemoryHigh` (3 times `maxMemoryMB`) and `MemoryMax` (4 times), written when the service is installed and not changed by later edits of `engine.json`. On macOS the launchd plist carries a `ResidentSetSize` of the same sizes, which current macOS does not enforce, so the engine's only limit there is `GOMEMLIMIT`.

## 4. Connect your MCP client

The agent registers the `basalt mcp` line the page showed. For Claude Code that is:

```sh
claude mcp add basalt-demo_bot -- /usr/local/bin/basalt mcp --agent demo_bot
```

Any other client takes the same command and arguments:

```json
{
  "mcpServers": {
    "basalt-demo_bot": {
      "command": "/usr/local/bin/basalt",
      "args": ["mcp", "--agent", "demo_bot"]
    }
  }
}
```

No database URL goes in the client config. The agent never holds one; the engine does. Start the client and check that `basalt-demo_bot` is connected with its tools (`run_start`, `query`, `write` and others).

## 5. First `query` and `write`

Give the agent these prompts.

**Read.**

> Use the basalt-demo_bot tools. Start a run with the intent "Qualify this week's leads", then read id, name, status and score of leads 1 to 10 from basalt_demo.leads in that run.

You get 10 rows, all `NEW`.

**Write.**

> Mark leads 1, 2 and 3 as QUALIFIED and add 10 to their score. Intent: "Qualify leads 1 to 3".

The result is `"status": "APPLIED"` with `"rows": 3`. A write with no intent is refused with `INTENT_REQUIRED`.

**A held write.**

> Mark every lead whose status is NEW as CONTACTED. Intent: "Mark new leads contacted".

A write of 11 to 50 rows, or any `DELETE`, is held. The agent shows you `Held for your approval: ...` with a link to `http://localhost:8787/approvals/<id>#s=...`. Open it, check the rows, and approve with your passkey. The agent's write returns `APPLIED` on its own. If you take longer than about 90 seconds, tell the agent you approved and it applies the write. The agent cannot approve; only your passkey can. More in [`approving.md`](approving.md).

**See the record and undo it.** Ask the agent what it did in the run, and to undo it. It reads the run with `run_history`, checks the rows with `preview_revert`, and gives you a link to a revert page. Check the rows and sign with your passkey. Rows a person changed after the agent are left as they are. [`approving.md`](approving.md) has the steps.

## Update

Once a day the engine looks at the public release list of BasaltDBHq/BasaltDB (nothing else is sent). When a newer release is out, the agent's `status` carries an `update` field and the agent tells you. To turn the check off, set `BASALT_UPDATE_CHECK=off` or `"updateCheck": "OFF"` in `engine.json`.

Upgrade the binary the way you installed it: `brew upgrade basaltdbhq/tap/basaltdb`, or install the new release over the old one at the same path (for the service, the root-owned copy it runs, for example `sudo install -o root -m 0755 basalt /usr/local/libexec/basalt`).

The engine restarts onto the new binary by itself, with or without the service, and in a container:

- It looks at the path it was started from every 5 seconds. Once the new file has stopped changing, it runs `basalt version` on it, and when it started from a root-owned binary it checks the new one is root-owned too.
- It waits for a moment when no agent call is running (up to 2 minutes), stops taking calls, closes its sockets and runs the new binary in the same process: same process id, same OS user, same files. Its log says `a new basalt binary is installed` and then `restarting onto the upgraded binary`.
- If the new binary fails a check, the log says why and the engine keeps serving on the old one.

To restart it by hand anyway:

- With the service: `sudo systemctl restart basalt-engine` on Linux, `sudo launchctl kickstart -k system/dev.basaltdb.engine` on macOS.
- Without a service (a bot machine, a container): stop the `basalt engine` process and start it again with the same command.

You do not restart your agent's MCP client. `basalt mcp`, the process the client started, only relays to the engine and keeps running; it waits up to 15 seconds for the engine to come back. A call the engine turned away because it was restarting was not run, so `basalt mcp` sends it to the new engine. A read the engine was answering when it stopped (`query`, `describe`, `list_pending`, `list_runs`, `run_history`, `status`) is sent once more to the new engine. A `write`, an approval or a revert that may have started is never sent twice: the agent is told the call may or may not have run, and it reads before it writes again.

Then, if the agent's `status` says the guard can be updated, ask the agent for the update link and run the update on that page; the engine serves again without a restart.

How the pieces talk, for reference: the client starts `basalt mcp` over stdio; it dials the engine's Unix socket for that agent and forwards each message. The engine holds the credential and talks to Postgres. When the engine is down, `basalt mcp` answers `status` and the tool list itself and every other call with `ENGINE_UNREACHABLE`.

**The guard in your database.** After a binary upgrade the agent's `status` may say the guard can be updated. Ask the agent to update it. It runs `basalt init`, and the link it gives you opens the setup page for that job. Type the admin connection string there. The update applies only the migrations your database lacks. It rotates no password and changes no grant or policy.

## Containers without systemd

A container usually has no service manager: PID 1 is your process or a small init such as `tini`. The administrator dialog cannot install the engine service there. BasaltDB has no container setup of its own: run `basalt engine --config /etc/basalt/engine.json` as an OS user other than the agent's, with that user's files (`0600` config and credential) only that user can read. The systemd unit's sandbox and memory limits do not exist without systemd; set a memory limit on the container yourself.

## If something is off

- `/mcp` shows the server failed, or the connection closes at once: the engine admits only the OS user the setup page named. Start the client as that user. The engine log is `/Library/Logs/Basalt/engine.log` on macOS and `journalctl -u basalt-engine` on Linux.
- The agent says the guard is outdated: ask it to update the guard, as in "Update" above.
- The agent reads zero rows from a table that has rows: row-level security is on with no policy for the agent. Ask the agent to run `basalt init` and answer the row-level security question for that table on the page.
- `basalt init` says the binary is not owned by root: the service runs only a copy that root owns and that group and others cannot change. Put `basalt` in a root-owned directory and run that copy.
- `basalt init` says there is no administrator dialog: it needs a desktop session. It never falls back to running the engine as your user.
- The page says `JOB_UNAVAILABLE`: the engine is agent-operated, or it already has a config and the job is an install. Ask the agent to run `basalt init` again and use the link it prints.

## Remove everything

Ask the agent to remove BasaltDB. It runs `basalt init`, and the link opens a page where you pick **Remove BasaltDB**. The page shows the SQL and, once you type the admin connection string and tick the confirmation, drops the `basalt_meta` schema (the ledger, for good), the guard's policies, and the `basalt_*` roles in one transaction, and removes the agent from the engine's config. It also drops the demo data (`basalt_demo`) when the schema carries the comment `BasaltDB demo data` and nothing of yours depends on it. It registers and asks for no passkey.

The page does not remove the engine service yet. Remove it yourself:

```sh
sudo basalt service uninstall
```

`service uninstall` stops and removes the engine service. Where `systemctl` or `launchctl` does not run, it still removes the unit file and names each command it skipped.

### What `service uninstall` leaves behind

`service uninstall` removes only the service unit. It keeps the rest on purpose, so that a new install finds its config and credentials and does not have to start over:

| Kept | Linux | macOS |
|---|---|---|
| Config directory: `engine.json` and `agents/<name>.url`, the agent's database credential | `/etc/basalt` | `/Library/Application Support/Basalt` |
| State directory: the engine's keys, PII dictionary, ledger chain heads and link secrets | `/var/lib/basalt` | `/Library/Application Support/Basalt/state` |
| Logs | none on disk; the engine logs to the journal (`journalctl -u basalt-engine`), which the system keeps | `/Library/Logs/Basalt`: the engine's `engine.log`, and in `plugins/` the stderr log of a plugin that is no longer installed (`service uninstall` deletes the logs of the plugins it removes). After an upgrade from an earlier release, the old logs are in `/Library/Logs/Basalt.old-<time>` |
| The engine's OS user and group | `basalt` | `_basalt` |

The socket directory (`/run/basalt` on Linux, `/Library/Application Support/Basalt/run` on macOS) holds only sockets and the engine's lock. It goes away on Linux when the service stops; on macOS it sits inside the config directory and goes with it.

Once the setup page removed BasaltDB, the credential in `agents/<name>.url` no longer works, so nothing in these files is live. To remove them, run this after `sudo basalt service uninstall`.

On Linux:

```sh
sudo rm -rf /etc/basalt /var/lib/basalt
sudo userdel basalt
```

`userdel` also removes the `basalt` group, which the install created with the user. Delete the group with `sudo groupdel basalt` if it is still listed.

On macOS:

```sh
sudo rm -rf "/Library/Application Support/Basalt" /Library/Logs/Basalt /Library/Logs/Basalt.old-*
sudo dscl . -delete /Users/_basalt
sudo dscl . -delete /Groups/_basalt
```

Remove the user last, after the files it owns. If you plan to install again, you can keep the config directory, the user and the state directory. The state directory holds each agent's ledger chain head. After a new install the engine sees that the head belongs to the old ledger, records that in the new ledger and starts a new head. The agent's `status` then carries a notice that the ledger was reinstalled, so that a reinstall nobody on your team made does not go unnoticed.

## Coming soon

- Your own tables on the local setup page.
- The hosted relay, which removes the pasted approval and revert codes on the portal.

For a bot on a server you cannot log in to, see [`bot-setup.md`](bot-setup.md).
