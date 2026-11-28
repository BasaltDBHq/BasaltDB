# Remove an older install

BasaltDB is in alpha, then beta. Those releases may break: a newer version cannot update an install an older one made. There is no migration across such a release: BasaltDB removes the old install and sets up again from scratch.

Removing BasaltDB deletes its ledger in that database: the record of what agents did, their held approvals and their passkeys. You cannot undo agent runs afterwards. Your own tables and rows stay as they are.

## The setup page does it

Upgrade `basalt` (from Homebrew: `brew uninstall --formula basaltdb`, then `brew install basaltdbhq/tap/basaltdb`), then ask your agent to run `basalt init`. The setup page it opens finds the old install and says so first: `This BasaltDB install is too old to update`, the release that set it up when the database records one (or its guard version), and the guard version this release needs. Then it runs the normal install steps. The last button, **Remove the old install and set up**, asks you to type the database's name, then removes the old install and installs the new one in one transaction. If the setup fails, the old install stays as it was.

The connect page does the same for an agent on a computer you cannot reach, once its service offers it.

To remove BasaltDB without setting it up again, while the install still works: open the link `basalt init` prints on an engine already set up, pick **Remove BasaltDB**, paste the admin connection string, and press **Remove BasaltDB from <database> on <host>**.

## If it is broken

When the page cannot read the install at all (`This database has an older BasaltDB install that this version cannot use`, `GUARD_UNUSABLE`), run this SQL in the database, as the database admin (the user in your admin connection string; on Supabase, `postgres` in the SQL editor). It runs in one transaction: if a statement fails, nothing changes.

First list the agent roles:

```sql
SELECT rolname FROM pg_roles WHERE rolname LIKE 'basalt\_agent\_%';
```

Then run the removal with one `GRANT` line and one `DROP OWNED` and `DROP ROLE` pair per agent role it listed (here one agent, `basalt_agent_demo_bot`):

```sql
BEGIN;
-- Make the admin a member of each role, so it may drop what they own.
-- Supabase needs this: postgres is not a superuser there.
GRANT basalt_agent_demo_bot TO CURRENT_USER;
GRANT basalt_agents TO CURRENT_USER;
GRANT basalt_guard TO CURRENT_USER;
-- The ledger, with the guard's functions and its triggers on your tables.
DROP SCHEMA IF EXISTS basalt_meta CASCADE;
-- Each agent role, then the agents group, then the guard role.
DROP OWNED BY basalt_agent_demo_bot;
DROP ROLE basalt_agent_demo_bot;
DROP OWNED BY basalt_agents;
DROP ROLE basalt_agents;
DROP OWNED BY basalt_guard;
DROP ROLE basalt_guard;
COMMIT;
```

`DROP OWNED` removes only what that role owns and the privileges and row-level security policies granted to it; it never drops your tables. A role that does not exist makes its `GRANT` fail: leave out the lines for roles the list did not show.

Check that nothing is left. This answers no row:

```sql
SELECT rolname FROM pg_roles WHERE rolname LIKE 'basalt%';
```

The sample data from a demo install, the `basalt_demo` schema, is yours to keep or drop (`DROP SCHEMA basalt_demo CASCADE`).

## Upgrading from 0.0.1: the computer

An install from 0.0.1 also left an engine on the computer that ran it, with its config at `/Library/Application Support/Basalt/` or `/etc/basalt/` (with the service), or in your own folder, `~/Library/Application Support/basalt/` (macOS) or `~/.config/basalt/` (Linux). `basalt init` resets it: it reads the config's shape, and a config from before the last breaking release is moved aside to `<folder>.old` (never deleted; delete it once the new setup works). For the system folder it does this in the administrator dialog it already shows, where it also stops and removes the old engine service and installs it again. It says so in one line, and prints the `basalt mcp --agent NAME` line your agent registers again.

Update the line your agent app runs to `basalt mcp --agent NAME`: 0.1 has no `--config` or `--socket-dir` on `basalt mcp`, and a line that still has them fails to connect. In Claude Code:

```sh
claude mcp remove NAME -s user
claude mcp add NAME -s user -- basalt mcp --agent NAME
```

If `basalt init` cannot do it (no administrator dialog, such as in an SSH session, or a 0.0.1 engine that serves no local pages and so is never restarted), do it by hand, once, in a terminal:

1. Stop and remove the old engine service, if 0.0.1 installed one. On macOS:

   ```sh
   sudo launchctl bootout system/dev.basaltdb.engine
   sudo rm -f /Library/LaunchDaemons/dev.basaltdb.engine.plist
   ```

   On Linux:

   ```sh
   sudo systemctl disable --now basalt-engine.service
   sudo rm -f /etc/systemd/system/basalt-engine.service
   sudo systemctl daemon-reload
   ```

2. Move the old config folder out of the way. It holds the old agent's credential file; delete it once 0.1 works.

   ```sh
   mv ~/Library/Application\ Support/basalt ~/Library/Application\ Support/basalt.old   # macOS
   mv ~/.config/basalt ~/.config/basalt.old                                              # Linux
   ```

   With the 0.0.1 service, its config is in the system folder instead:

   ```sh
   sudo mv "/Library/Application Support/Basalt" "/Library/Application Support/Basalt.old"   # macOS
   sudo mv /etc/basalt /etc/basalt.old                                                       # Linux
   ```

3. Update the binary: `brew uninstall --formula basaltdb`, then `brew install basaltdbhq/tap/basaltdb`, or install the new archive or package.

4. Ask your agent to run `basalt init`: the setup page replaces the old install in the database.

## The engine still holds the old setup

When the database is clean but the engine on your computer is still set up for it, run `basalt init`. It opens the page that asks `Is this your database?`. Answer **No, this isn't mine** and type your computer's administrator password in the dialog that opens: it deletes BasaltDB's setup on this computer and touches no database. `basalt init` then opens a new install link.
