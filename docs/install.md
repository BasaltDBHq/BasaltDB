# Install guide

From nothing to your agent's first guarded write. It works with Supabase and with any plain Postgres you can log in to as an admin (RDS, self-hosted).

Type your database's admin connection string only on the setup page, never to the agent.

You need:

- macOS or Linux, with a desktop session. The first install asks for your administrator password in the system's own dialog. On a machine with no desktop, such as an SSH session, setup stops there; for a bot on a machine you cannot reach, use [bot-setup.md](bot-setup.md).
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
curl -fsSL -O https://github.com/BasaltDBHq/BasaltDB/releases/download/v0.1.0-alpha/basaltdb_0.1.0-alpha_linux_amd64.tar.gz
curl -fsSL -O https://github.com/BasaltDBHq/BasaltDB/releases/download/v0.1.0-alpha/SHA256SUMS
grep 'basaltdb_0.1.0-alpha_linux_amd64.tar.gz$' SHA256SUMS | sha256sum -c -
tar -xzf basaltdb_0.1.0-alpha_linux_amd64.tar.gz
```

#### Check the signature

Releases after `v0.0.1-alpha.2` also carry `SHA256SUMS.sigstore.json`, a [Sigstore](https://www.sigstore.dev/) signature of `SHA256SUMS`. The release workflow signs it with no long-lived key: [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) gets a short-lived certificate for the workflow's GitHub identity, and the signature is recorded in the public Rekor transparency log. A valid signature proves that `SHA256SUMS` came from this repository's release workflow, run for that tag. Since `SHA256SUMS` lists every archive, package and `portal.sha256`, checking the archive against it (above) then covers the archive too.

With `cosign` 2.5 or later installed (the bundle is in the Sigstore bundle format), check the signature before you check the archive:

```sh
TAG=v0.1.0-alpha   # the release you downloaded
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

Paste it on the setup page only. If you paste it to your agent by mistake, change that database password now.

### Databases signed by their own CA

Supabase and Amazon RDS hosts verify with no extra step. Google Cloud SQL, DigitalOcean, Aiven and self-signed databases use a CA per instance or project. For those, the setup page shows the certificate and asks whether to trust it for that host only. Check the SHA-256 it shows against your provider's console before you say yes. A pin on your provider's own CA accepts any certificate that CA signs, so where the provider shares one CA across customers, someone who is both another customer and on the network path to your database could pose as it. Your password still stays off the wire, because Postgres signs in with SCRAM.

### Connections

Each agent's engine opens up to 4 connections to the database, plus 1 while the `status` tool runs. Postgres caps each agent role at 8 connections (`CONNECTION LIMIT 8`).

Budget for it. The number of agents times 8 must fit next to your app's own connections, within the limit your database allows in total.

**On Supabase.** The smallest instance allows roughly 60 direct connections in total. The session pooler (port 5432 on the pooler host, the string recommended above) gives each client connection its own server connection from a shared pool. Count every engine connection against that pool. Transaction mode (port 6543) would share server connections, but it is not yet verified with Basalt. Do not rely on it.

If it does not fit, run fewer agents per database or move to a bigger instance.

When an agent hits its cap, its `status` tool reports `TOO_MANY_CONNECTIONS` with this message:

> The agent <name> has used all 8 database connections Basalt allows it. Another engine for the same agent may be running, or a stopped engine left sessions open. Stop any second engine; stale sessions close on their own within a few minutes.

## 3. Set up with the sample database

Ask your agent to set up BasaltDB with the sample data.

1. Enter your administrator password when your system asks, once. It copies `basalt` into a folder only root can change (`/usr/local/libexec/basalt` on macOS, `/usr/libexec/basalt` on Linux), creates the engine's OS user (`_basalt` on macOS, `basalt` on Linux) and starts the engine as a service from that copy. `basalt` itself can sit anywhere, a Homebrew prefix or a folder of your own included.
2. A setup page opens at `http://localhost:8787/setup/`. Your agent shows you the same link if the browser did not open. Port 8787 must be free: `lsof -nP -iTCP:8787 -sTCP:LISTEN` shows what holds it.
3. Check that the page names the OS user your agent runs as. Paste the admin connection string, press **Check**, read the SQL, and press **Set up**. If the database has no passkey for this page, the browser asks you to register one first.
4. The page ends with `demo ready: leads 30, lead_notes 20`, the `basalt mcp` line for your agent, and your passkey's check code.

You get the schema `basalt_demo` with `leads` (30 rows) and `lead_notes` (20 rows), the agent `demo_bot` with write access to those two tables and nothing else, the `basalt_meta` guard schema and the `basalt_*` roles. The SQL runs in one transaction. Running setup again keeps the demo rows and the agent's password.

An agent that runs as your own OS user could show you a fake `localhost` page that asks for the admin string, or replace a `basalt` binary in a folder you can write to before the password dialog copies it. Before you paste the admin string, check the address bar (`localhost:8787`) and the OS user the page names. Signing stays safe either way: Postgres checks the page's exact origin, port included.

Check the engine:

```sh
curl -s http://localhost:8787/healthz
```

It prints `ok`.

### Engine memory

The engine keeps its PII dictionary within `pii.maxMemoryMB` in `engine.json` (default 512). It sets the Go memory limit (`GOMEMLIMIT`) to twice that unless you set `GOMEMLIMIT` yourself. The service's unit carries limits of its own: on Linux, systemd `MemoryHigh` (3 times `maxMemoryMB`) and `MemoryMax` (4 times), written when the service is installed and not changed by later edits of `engine.json`. On macOS the launchd plist carries a `ResidentSetSize` of the same sizes, which current macOS does not enforce, so the engine's only limit there is `GOMEMLIMIT`.

## 4. Connect your MCP client

Register the `basalt mcp` line the page showed in your MCP client. For Claude Code:

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

Do not put a database URL in the client config. Start the client and check that `basalt-demo_bot` is connected with its tools (`run_start`, `query`, `write` and others).

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

**See the record and undo it.** Ask the agent what it did in the run, then to undo it. Open the link it gives you, check the rows and sign with your passkey. Rows you changed after the agent are left as they are. [`approving.md`](approving.md) has the steps.

## Update

When a newer release is out, your agent tells you. The engine checks the public release list of BasaltDBHq/BasaltDB once a day and sends nothing else. To turn the check off, set `BASALT_UPDATE_CHECK=off` or `"updateCheck": "OFF"` in `engine.json`.

Upgrade the binary the way you installed it: `brew upgrade basaltdbhq/tap/basaltdb`, or install the new release over the old one at the same path. Then ask your agent to run `basalt init`: the engine service runs its own copy of `basalt`, so `init` sees the engine runs another build and asks for your password once, to copy the new `basalt` over the service's copy and restart the engine onto it. When the release needs a newer guard, pick Update on the page `init` opens; `init` ends as soon as the update is done, and the agent goes on.

Without the service (a bot machine, a container), and with the service when its own copy changes, the engine restarts onto the new binary by itself:

- It looks at the path it was started from every 5 seconds. Once the new file has stopped changing, it runs `basalt version` on it, and when it started from a root-owned binary it checks the new one is root-owned too.
- It waits for a moment when no agent call is running (up to 2 minutes), stops taking calls, closes its sockets and runs the new binary in the same process: same process id, same OS user, same files. Its log says `a new basalt binary is installed` and then `restarting onto the upgraded binary`.
- If the new binary fails a check, the log says why and the engine keeps serving on the old one.

To restart it by hand anyway:

- With the service: `sudo systemctl restart basalt-engine` on Linux, `sudo launchctl kickstart -k system/dev.basaltdb.engine` on macOS.
- Without a service (a bot machine, a container): stop the `basalt engine` process and start it again with the same command.

You do not restart your agent's MCP client. `basalt mcp`, the process the client started, only relays to the engine and keeps running; it waits up to 15 seconds for the engine to come back. A call the engine turned away because it was restarting was not run, so `basalt mcp` sends it to the new engine. A read the engine was answering when it stopped (`query`, `describe`, `list_pending`, `list_runs`, `run_history`, `status`) is sent once more to the new engine. A `write`, an approval or a revert that may have started is never sent twice: the agent is told the call may or may not have run, and it reads before it writes again.

Then, if the agent's `status` says the guard can be updated, ask the agent for the update link and run the update on that page; the engine serves again without a restart.

How the pieces talk, for reference: the client starts `basalt mcp` over stdio; it dials the engine's Unix socket for that agent and forwards each message. The engine holds the credential and talks to Postgres. When the engine is down, `basalt mcp` answers `status` and the tool list itself and every other call with `ENGINE_UNREACHABLE`.

**The guard in your database.** After a binary upgrade your agent may say the guard can be updated. Ask it to update the guard, open the link it gives you, and paste the admin connection string there. The update applies only the migrations your database lacks. It changes no password, grant or policy.

## Containers without systemd

A container usually has no service manager: PID 1 is your process or a small init such as `tini`. The administrator dialog cannot install the engine service there. BasaltDB has no container setup of its own: run `basalt engine --config /etc/basalt/engine.json` as an OS user other than the agent's, with that user's files (`0600` config and credential) only that user can read. The systemd unit's sandbox and memory limits do not exist without systemd; set a memory limit on the container yourself.

## If something is off

- `/mcp` shows the server failed, or the connection closes at once: the engine admits only the OS user the setup page named. Start the client as that user. The engine log is `/Library/Logs/Basalt/engine.log` on macOS and `journalctl -u basalt-engine` on Linux.
- Your agent says the guard is outdated: update it as in "Update" above.
- Your agent reads zero rows from a table that has rows: row-level security is on with no policy for the agent. Ask your agent for a new setup link and answer the row-level security question for that table on the page.
- Setup says the service's copy of `basalt` is not owned by root, or could not be copied: the service runs only a copy that root owns and that group and others cannot change, which the password dialog makes. Ask your agent to run `basalt init` again.
- Setup says there is no administrator dialog: it needs a desktop session.
- The page says `JOB_UNAVAILABLE`: the engine is run by a bot, or it is already set up and the page was an install. Ask your agent for a new link.
- The page says `GUARD_UNUSABLE`: the database has an older BasaltDB install this version cannot use. Remove it as [Remove an older install](remove-old-install.md) says, then set up again.
- The page says `SETUP_FAILED` with a Postgres error code: the engine log has the step and the database's message.

## Remove everything

An install a newer alpha or beta cannot use, or one too broken for the page's Remove: see [Remove an older install](remove-old-install.md).

Ask your agent to remove BasaltDB. On the page that opens, pick **Remove BasaltDB**, paste the admin connection string, read the SQL and type the database's name to confirm. In one transaction it drops the `basalt_meta` schema (the ledger goes for good), the guard's policies and the `basalt_*` roles, and removes the agent from the engine's config. It also drops the demo data (`basalt_demo`) when the schema carries the comment `BasaltDB demo data` and nothing of yours depends on it. It asks for no passkey.

If you remove within 90 seconds of the page opening, your computer then asks for your password once, in its own administrator dialog. Otherwise the page says **Last step**: ask your agent to finish removing BasaltDB, and the dialog comes when it runs `basalt init` once more. That stops and removes the engine service, and everything it put on the computer:

| Removed | Linux | macOS |
|---|---|---|
| The service unit | `/etc/systemd/system/basalt-engine.service` | `/Library/LaunchDaemons/dev.basaltdb.engine.plist` |
| The service's copy of `basalt` | `/usr/libexec/basalt` | `/usr/local/libexec/basalt` |
| Config directory: `engine.json` and the agents' credentials | `/etc/basalt` | `/Library/Application Support/Basalt` |
| State directory: the engine's keys, PII dictionary, ledger chain heads and link secrets | `/var/lib/basalt` | `/Library/Application Support/Basalt/state` |
| Socket directory | `/run/basalt` | `/Library/Application Support/Basalt/run` |
| Logs | none on disk; the journal keeps what the engine logged | `/Library/Logs/Basalt`, and `/Library/Logs/Basalt.old-*` from an upgrade |
| Plugins: their service units, installed copies, trusted keys, sockets, logs and log rules | `/etc/systemd/system/basalt-plugin-*.service`, `/opt/basalt` | `/Library/LaunchDaemons/dev.basaltdb.plugin-*.plist`, `/etc/newsyslog.d/basalt-plugin-*.conf`, `/Library/Basalt` |
| OS users and groups | `basalt` and every `basalt-plugin-*` | `_basalt` and every `_basalt-plugin-*` |

The service stays when the engine still serves an agent of another database: remove that one too, and the service goes with the last. An OS user that can log in is never deleted; the dialog names it instead. If you close the dialog, ask your agent again: the dialog comes back, with no page.

**Limit: a restart in between.** If the computer restarted after the page's Remove and before the dialog ran, the engine has no config and waits for a new install, so the agent can no longer finish the removal. Remove the service by hand then. On Linux:

```sh
sudo systemctl disable --now basalt-engine.service
sudo rm -f /etc/systemd/system/basalt-engine.service /etc/systemd/system/basalt-plugin-*.service
sudo systemctl daemon-reload
sudo rm -rf /etc/basalt /var/lib/basalt /opt/basalt
sudo rm -f /usr/libexec/basalt
sudo userdel basalt
```

On macOS:

```sh
sudo launchctl bootout system/dev.basaltdb.engine
sudo rm -f /Library/LaunchDaemons/dev.basaltdb.engine.plist /Library/LaunchDaemons/dev.basaltdb.plugin-*.plist /etc/newsyslog.d/basalt-plugin-*.conf
sudo rm -rf "/Library/Application Support/Basalt" /Library/Logs/Basalt /Library/Logs/Basalt.old-* /Library/Basalt
sudo rm -f /usr/local/libexec/basalt
sudo dscl . -delete /Users/_basalt
sudo dscl . -delete /Groups/_basalt
```

Plugin OS users (`basalt-plugin-*`, `_basalt-plugin-*`) are deleted the same way, with `userdel` or `dscl`.

For a bot on a server you cannot log in to, see [`bot-setup.md`](bot-setup.md).
