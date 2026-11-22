# Remove an older install

BasaltDB is in alpha, then beta. Those releases may break: a newer version can refuse an install an older one made. The setup page then says `This database has an older BasaltDB install that this version cannot use` (`GUARD_UNUSABLE`). The fix is a clean install: remove the old install, then set up again.

Removing BasaltDB deletes its ledger in that database: the record of what agents did, their held approvals and their passkeys. You cannot undo agent runs afterwards. Your own tables and rows stay as they are.

## If the install still works

Use the setup page's Remove. Run `basalt init` on the computer that runs the engine, open the Update or Remove link it prints, pick **Remove BasaltDB**, paste the admin connection string, and type the database's name to confirm. Then ask your agent for a new setup link and install again.

## If it is broken, or too old for Remove

Run this SQL in the database, as the database admin (the user in your admin connection string; on Supabase, `postgres` in the SQL editor). It runs in one transaction: if a statement fails, nothing changes.

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

## The engine still holds the old setup

When the database is clean but the engine on your computer is still set up for it, run `basalt init`. It opens the page that asks `Is this your database?`. Answer **No, this isn't mine** and type your computer's administrator password in the dialog that opens: it deletes BasaltDB's setup on this computer and touches no database. `basalt init` then opens a new install link.
