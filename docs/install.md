# Install guide

From nothing to your agent's first guarded write, in about three minutes. It works with Supabase and with any plain Postgres you can log in to as an admin (RDS, Neon, self-hosted).

You need:

- macOS or Linux, with `sudo`.
- Go 1.26 or newer, and `git`. (There is no download for this version yet; see [Coming soon](#coming-soon).)
- A Postgres you own. You need its admin connection string, the one for the `postgres` user.
- A browser on the same machine, with a passkey (Touch ID, a security key, or your phone through the browser).
- An MCP client. Examples below use Claude Code; [`mcp-clients.md`](mcp-clients.md) has the JSON for others.

The admin connection string is used once, by `basalt init`, typed into its hidden prompt. It is never stored. Do not export it or put it on a command line.

## 1. Build and install `basalt`

```sh
git clone https://github.com/BasaltDBHq/BasaltDB.git
cd BasaltDB
go build -o basalt ./cmd/basalt
sudo mkdir -p /usr/local/bin && sudo install -m 0755 basalt /usr/local/bin/basalt
basalt version
```

`basalt version` prints the version. The engine will run as its own OS user from this path, so keep the binary somewhere every user can read, not in your home directory.

## 2. Get the connection string

**Supabase.** In the dashboard press **Connect** and copy the string that matches your network:

| String | Use it |
|---|---|
| Session pooler, port 5432 (`postgres.<ref>@aws-0-<region>.pooler.supabase.com`) | If unsure. Works on IPv4 and IPv6. |
| Direct connection (`db.<ref>.supabase.co`) | Only if your network has IPv6. |

Fill in `[PASSWORD]` with your database password, URL-encoding characters such as `@`, `/`, `:` and `#`. Add `?sslmode=require` at the end.

**Plain Postgres.** `postgresql://postgres:PASSWORD@HOST:5432/DBNAME?sslmode=require`

## 3. Create a table to guard (skip if you have one)

[`docs/m4/seed.sql`](m4/seed.sql) creates a schema `basalt_demo` with `leads` (30 rows) and `lead_notes` (20 rows). Nothing else is touched.

- Supabase: paste the file into the SQL editor and run it.
- Plain Postgres: `psql -h HOST -U postgres DBNAME -f docs/m4/seed.sql` (psql asks for the password).

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

**See the record and undo it.** Both commands read the agent's credential, which belongs to the engine's user, so they run as that user (`_basalt` on macOS, `basalt` on Linux). `RUN_ID` is the run id the agent returned from `run_start`.

```sh
sudo -u _basalt basalt log --agent demo_bot --run RUN_ID
sudo -u _basalt basalt revert --agent demo_bot --run RUN_ID
```

`revert` prints a link to the revert page. It runs as the engine user, which has no browser session, so open the link yourself, check the rows, and sign with your passkey. The page shows a code; paste it at the `Paste the code the revert page showed:` prompt. Rows a person changed after the agent are left as they are.

## If something is off

- `tables ... not found in database`: step 3 did not run in this database, or the connection string points at another one. Init checks first and changes nothing.
- The agent reads zero rows from a table that has rows: row-level security is on with no policy for the agent. Run step 4 again and answer `y` to the row-level security question, or add `--agent-rls=all-rows`.
- `/mcp` shows the server failed, or the connection closes at once: the engine admits only the OS user that ran `init` (`--os-user`, you by default). Start the client as that user. The engine log is `/Library/Logs/Basalt/engine.log` on macOS and `journalctl -u basalt-engine` on Linux.
- `guard schema vN is older than this build's vM`: run the `basalt init` command from step 4 again with the same flags. It keeps the agent's password.
- No `sudo`, or you do not want a service: add `--no-service` to `basalt init`. It then prints the one `basalt engine --config ...` command to run in the foreground as you. Writes are still guarded in Postgres, but your user can read the agent's credential file. [`m4-runbook.md`](m4-runbook.md) walks that mode end to end.

## Remove everything

```sh
basalt uninstall
sudo basalt service uninstall
```

`basalt uninstall` asks for the admin connection string, then drops the `basalt_meta` schema, the guard's triggers and policies, and the `basalt_*` roles. `service uninstall` stops and removes the engine service. If you used the demo data, drop it too: `DROP SCHEMA basalt_demo CASCADE;`.

## Coming soon

- A release download. The published release predates the guard, so for now you build from source (step 1).
- Setting up the guard from a laptop for an engine on another machine, and a status command.
