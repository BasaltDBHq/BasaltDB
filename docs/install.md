# Install guide

From nothing to your agent's first guarded write, in about three minutes. It works with Supabase and with any plain Postgres you can log in to as an admin (RDS, self-hosted).

You need:

- macOS and Linux.
- A Postgres you own. You need its admin connection string, the one for the `postgres` user.
- A browser on the same machine, with a passkey (your laptop's own, a security key, or your phone through the browser).
- An MCP client. Examples below use Claude Code; [`mcp-clients.md`](mcp-clients.md) has the JSON for others.

The admin connection string is used once, by `basalt init`, typed into its hidden prompt. It is never stored. Do not export it or put it on a command line.

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

### Connections

Each agent's engine opens up to 4 connections to the database, plus 1 while `basalt status` runs. Postgres caps each agent role at 8 connections (`CONNECTION LIMIT 8`).

Budget for it. The number of agents times 8 must fit next to your app's own connections, within the limit your database allows in total.

**On Supabase.** The smallest instance allows roughly 60 direct connections in total. The session pooler (port 5432 on the pooler host, the string recommended above) gives each client connection its own server connection from a shared pool. Count every engine connection against that pool. Transaction mode (port 6543) would share server connections, but it is not yet verified with Basalt. Do not rely on it.

If it does not fit, run fewer agents per database or move to a bigger instance.

When an agent hits its cap, `basalt status` reports `TOO_MANY_CONNECTIONS` with this message:

> The agent <name> has used all 8 database connections Basalt allows it. Another engine for the same agent may be running, or a stopped engine left sessions open. Stop any second engine; stale sessions close on their own within a few minutes.

## 3. Create a table to guard (skip if you have one)

[`examples/demo/seed.sql`](../examples/demo/seed.sql) creates a schema `basalt_demo` with `leads` (30 rows) and `lead_notes` (20 rows). Nothing else is touched.

- Supabase: paste the file into the SQL editor and run it.
- Plain Postgres: `psql -h HOST -U postgres DBNAME -f examples/demo/seed.sql` (psql asks for the password).

To guard your own tables instead, use them in step 4 in place of `basalt_demo.leads` and `basalt_demo.lead_notes`.

## 4. Install the guard: `basalt init`

```sh
basalt init --agent demo_bot \
  --write basalt_demo.leads --read basalt_demo.lead_notes
```

`--write` lists tables the agent may read and write, `--read` tables it may only read. Both take a comma-separated list of `schema.table`. Init asks, in order:

1. `Admin connection string (used once, never stored):` Paste the string from step 2. Nothing is echoed.
2. It prints the setup SQL, then `Run this SQL as postgres? [y/N]`. Type `y`.
3. `basalt: guard installed; agent role basalt_agent_demo_bot`
4. It prints a `http://localhost:8787/passkeys/register#...` link. Open it, press the button, confirm with your passkey, copy the `basalt-passkey.1....` code the page shows, and paste it at `Paste the code the page shows:`. Then `basalt: passkey registered for localhost`.
5. `Install the engine as a background service? This creates the OS user _basalt and needs your password once. [Y/n]` Press Enter. (On Linux the user is `basalt`.) Init runs one `sudo`, installs and starts the service, then checks it:

   `basalt: engine running as _basalt; it answered on /Library/Application Support/Basalt/run/demo_bot.sock` (on Linux, `/run/basalt/demo_bot.sock`)

   It then prints the MCP command to use in step 5.

If init asks `... hides its rows with row-level security. Let demo_bot see all 30 rows of this table? [y/N]`, row-level security is on for that table and no policy lets the agent see rows. Answer `y` to add a policy for the agent role only; with `n` the agent reads zero rows. Supabase can turn row-level security on for every new table, so this can happen with the demo tables too.

Port 8787 must be free while init waits for the passkey and afterwards for the engine. If it is taken, init says so; `lsof -nP -iTCP:8787 -sTCP:LISTEN` shows what holds it.

Check the engine:

```sh
curl -s http://localhost:8787/healthz
```

It prints `ok`.

### Engine memory

The engine keeps its PII dictionary within `pii.maxMemoryMB` in `engine.json` (default 512). It sets the Go memory limit (`GOMEMLIMIT`) to twice that unless you set `GOMEMLIMIT` yourself. `basalt service install` also writes limits into the service:

- **Linux:** the systemd unit gets `MemoryHigh` (3 × `maxMemoryMB`) and `MemoryMax` (4 ×). These are written when the service is installed and do not follow later edits of `engine.json`. After you raise `pii.maxMemoryMB`, run `sudo basalt service install` again with the same flags, or systemd may throttle or stop the engine below its new budget.
- **macOS:** the launchd plist gets `SoftResourceLimits` and `HardResourceLimits` with a `ResidentSetSize` of the same sizes, but current macOS does not enforce `ResidentSetSize`. The engine's only memory limit there is `GOMEMLIMIT`. Under memory pressure the OS can still evict the pages of the memory-mapped dictionary file.

## 5. Wire your MCP client

Claude Code:

```sh
claude mcp add basalt-demo_bot -- /usr/local/bin/basalt mcp --agent demo_bot
```

(If the `claude` CLI was on your `PATH`, init offered to run this and may have done it already.) Start `claude` and run `/mcp`: `basalt-demo_bot` should show as connected with its tools (`run_start`, `query`, `write` and others).

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

No database URL goes in the client config. The agent never holds one; the engine does.

## 6. First `query` and `write`

Give the agent these prompts.

**Read.**

> Use the basalt-demo_bot tools. Start a run with the intent "Qualify this week's leads", then read id, name, status and score of leads 1 to 10 from basalt_demo.leads in that run.

You get 10 rows, all `NEW`.

**Write.**

> Mark leads 1, 2 and 3 as QUALIFIED and add 10 to their score. Intent: "Qualify leads 1 to 3".

The result is `"status": "APPLIED"` with `"rows": 3`. A write with no intent is refused with `INTENT_REQUIRED`.

**A held write.**

> Mark every lead whose status is NEW as CONTACTED. Intent: "Mark new leads contacted".

A write of 11 to 50 rows, or any `DELETE`, is held. The agent shows you `Held for your approval: ...` with a `http://localhost:8787/approvals/<id>#s=...` link. Open it, check the rows, and approve with your passkey. The agent's write returns `APPLIED` on its own. If you take longer than about 90 seconds, tell the agent you approved and it applies the write. The agent cannot approve; only your passkey can. More in [`approving.md`](approving.md).

**See the record and undo it.** Run both as yourself, without `sudo`. You cannot read the engine's config or the agent's credential, so the commands ask the running engine over its person socket, which admits only the OS users `basalt init` recorded as the person (`--person-uid`, by default the person who ran it). `RUN_ID` is the run id the agent returned from `run_start`.

```sh
basalt log --agent demo_bot --run RUN_ID
basalt revert --agent demo_bot --run RUN_ID
```

`basalt approve --agent demo_bot` works the same way. `revert` prints a link to the revert page. Open it, check the rows, and sign with your passkey. If the page shows a code, paste it at the `Paste the code the revert page showed:` prompt. Rows a person changed after the agent are left as they are.

If the engine is stopped, these commands say so and print the command that starts it. If your OS user is not recorded, they print the `basalt init --person-uid` command that adds it.

**When the agent runs as you.** If you leave out `--os-user`, the agent runs as your own OS user, and `basalt init` prints a warning beginning `basalt: warning: the agent runs as OS user ..., which is also the person the engine admits on its person socket`. The engine cannot tell two processes of the same OS user apart, so while you and the agent share a user:

- `basalt log`, `approve` and `revert` over the socket see only this agent's ledger.
- The agent can run these commands too. It still cannot approve a held write or sign a revert, because both need your passkey.

To keep the agent off the person socket, run it as its own OS user: `basalt init --os-user <user>`.

## Containers without systemd

A container usually has no service manager: PID 1 is your process or a small init such as `tini`, so `basalt init` cannot install the engine service there. Run the engine as its own OS user with `basalt engine --user` instead, started as root by the container's entrypoint:

```sh
tini -- basalt engine --user basalt --config /etc/basalt/engine.json
```

Before it reads anything, the engine:

1. Refuses to go on unless it runs as root or already as `basalt`, and refuses `--user root` and a user whose group, or one of whose groups, is root's (gid 0).
2. Refuses a `basalt` binary anyone but root could change (the same check as `basalt service install`, step 1).
3. Makes `/run/basalt` (`0755`, for the sockets) and `/var/lib/basalt` (`0700`, its state), owned by `basalt`, as the systemd unit would.
4. Sets the supplementary groups, the group and the user to `basalt`'s, sets the umask to `0077` and, on Linux, `no_new_privs`, then checks that every thread runs as `basalt` with no capability left and that root cannot be taken back.

Only then does it open `engine.json`, the agent's credential, the sockets and the pages port. Its first log line is `basalt engine: dropped root; running as basalt (uid ..., gid ...); no_new_privs set`. A failed step stops it with nothing read.

**What does not apply.** The systemd unit's sandbox (`ProtectSystem`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, the kernel and cgroup protections) and its memory limits (`MemoryHigh`, `MemoryMax`, see [Engine memory](#engine-memory)) do not exist without systemd. The engine keeps `GOMEMLIMIT`; set a memory limit on the container yourself. In a container, **the OS user split is what protects the credential**: the config and the credential are `0600` files of `basalt`, and the agent must run as another OS user, best in another container that mounts only the socket directory.

**Setup.** Until `basalt init` sets up a container itself, run it once as the engine's user with explicit paths, so the files it writes are that user's: `basalt init --agent NAME --os-user AGENT_USER --config /etc/basalt/engine.json --socket-dir /run/basalt ...`. The `--os-user` must exist in the engine's container with the uid the agent runs as, and `/etc/basalt` must exist, owned by `basalt`, mode `0750`. Init then prints the foreground start command; use `basalt engine --user basalt --config /etc/basalt/engine.json` as the container's command instead.

[`examples/compose`](../examples/compose/README.md) is a tested `docker compose` setup: Postgres, the engine, and an agent container that shares only the socket volume.

On macOS `--user` works the same way when started as root (a launchd job you write yourself), with `/Library/Application Support/Basalt/run` and `.../state` as the directories, but macOS has no `no_new_privs`. The engine runs no other program, so there is nothing for it to stop.

## If something is off

- `tables ... not found in database`: step 3 did not run in this database, or the connection string points at another one. Init checks first and changes nothing.
- The agent reads zero rows from a table that has rows: row-level security is on with no policy for the agent. Run step 4 again and answer `y` to the row-level security question, or add `--agent-rls=all-rows`.
- `/mcp` shows the server failed, or the connection closes at once: the engine admits only the OS user that ran `init` (`--os-user`, you by default). Start the client as that user. The engine log is `/Library/Logs/Basalt/engine.log` on macOS and `journalctl -u basalt-engine` on Linux.
- `guard schema vN is older than this build's vM`: run the `basalt init` command from step 4 again with the same flags. It keeps the agent's password.
- If `basalt init` or `basalt service install` says the binary is not owned by root: the engine service will only run a copy that root owns and that group and others cannot change. Put `basalt` in a root-owned directory and run that copy, or use `--no-service`.
- No `sudo`, or you do not want a service: add `--no-service` to `basalt init`. It then prints the one `basalt engine --config ...` command to run in the foreground as you. Writes are still guarded in Postgres, but your user can read the agent's credential file. [`m4-runbook.md`](m4-runbook.md) walks that mode end to end.

## Remove everything

```sh
basalt uninstall
sudo basalt service uninstall
```

`basalt uninstall` asks for the admin connection string, then drops the `basalt_meta` schema, the guard's triggers and policies, and the `basalt_*` roles. `service uninstall` stops and removes the engine service. Where `systemctl` or `launchctl` does not run (a container without systemd), it still removes the unit file and names each command it skipped. Where the service manager does run, a skipped command makes it exit with an error after it has removed the rest. Once the unit file is gone there is nothing to stop, so running it again succeeds. `basalt uninstall` also drops the demo data (`basalt_demo`) when the schema carries the comment `BasaltDB demo data`.

### What `service uninstall` leaves behind

`service uninstall` removes only the service unit. It keeps the rest on purpose, so that running `basalt init` again finds its config and credentials and does not have to start over:

| Kept | Linux | macOS |
|---|---|---|
| Config directory: `engine.json` and `agents/<name>.url`, the agent's database credential | `/etc/basalt` | `/Library/Application Support/Basalt` |
| State directory: the engine's keys, PII dictionary, ledger chain heads and link secrets | `/var/lib/basalt` | `/Library/Application Support/Basalt/state` |
| Logs | none on disk; the engine logs to the journal (`journalctl -u basalt-engine`), which the system keeps | `/Library/Logs/Basalt` |
| The engine's OS user and group | `basalt` | `_basalt` |

The socket directory (`/run/basalt` on Linux, `/Library/Application Support/Basalt/run` on macOS) holds only sockets and the engine's lock. It goes away on Linux when the service stops; on macOS it sits inside the config directory and goes with it.

Once you have run `basalt uninstall`, the credential in `agents/<name>.url` no longer works, so nothing in these files is live. To remove them, run this after `sudo basalt service uninstall`.

On Linux:

```sh
sudo rm -rf /etc/basalt /var/lib/basalt
sudo userdel basalt
```

`userdel` also removes the `basalt` group, which `service install` created with the user. Delete the group with `sudo groupdel basalt` if it is still listed.

On macOS:

```sh
sudo rm -rf "/Library/Application Support/Basalt" /Library/Logs/Basalt
sudo dscl . -delete /Users/_basalt
sudo dscl . -delete /Groups/_basalt
```

Remove the user last, after the files it owns. If you plan to run `basalt init` again, you can keep the config directory, the user and the state directory. The state directory holds each agent's ledger chain head. After a new install the engine sees that the head belongs to the old ledger, records that in the new ledger and starts a new head. `basalt status` and `basalt log` then show a notice that the ledger was reinstalled, so that a reinstall nobody on your team made does not go unnoticed.

## Coming soon

- Browser-only setup, for a person without a terminal, and the hosted relay that removes the pasting of approval codes.

For a bot on a server you cannot log in to, see [`setup-from-laptop.md`](setup-from-laptop.md) (for you) and [`bot-setup.md`](bot-setup.md) (for the bot).
