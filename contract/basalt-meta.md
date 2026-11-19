## `basalt_meta`

- Everything BasaltDB installs lives in the `basalt_meta` schema and is removed with `DROP SCHEMA basalt_meta CASCADE`.
- The agent role has no direct `INSERT` on `basalt_meta` tables; ledger rows go through validating `SECURITY DEFINER` functions.
- Session settings use the `basalt.` prefix and are set transaction-local with `set_config(name, value, true)` (`SET LOCAL`), never session-level `SET`: `basalt.intent` (required on every agent write), `basalt.run_id`, `basalt.task_id`, `basalt.mode` (`APPLY` default, `PREVIEW`), `basalt.approval_id` (M2). The engine and `basalt revert` also set `TimeZone`, `DateStyle`, `IntervalStyle`, `extra_float_digits`, `lc_monetary` and `bytea_output` this way in every transaction ([Wire format](../CONTRACT.md#wire-format), Timestamps), so row values print the same from any session; the guard's row trigger and the revert's row read and restore set them on themselves (versions 34 and 35).
- Every BasaltDB connection to Postgres (engine and CLI) works through a transaction-mode pooler: it sends unnamed statements in one round trip (pgx `QueryExecModeExec`, `internal/pgdial`), never named prepared statements, unless the connection string sets `default_query_exec_mode`.
- Schema changes to `basalt_meta` are forward-only and versioned; the installed version is recorded in `basalt_meta.schema_version`. Agent roles may `SELECT` it: the engine reads it on every agent tool call and compares the recorded versions with the ones its build installs (to an agent that cannot read the table every version is missing). AE-11: each migration is flagged **breaking** (the default) or **non-breaking**; marking one non-breaking needs a test that runs the engine against a guard without that migration. A missing breaking migration serves the agent degraded (`status` only, every other tool `UNAVAILABLE` `GUARD_OUTDATED` with the `basalt upgrade` steps); missing only non-breaking ones serve normally with `GUARD_UPGRADE_AVAILABLE`. The engine checks again on each call, so `basalt upgrade` needs no restart.
- Every function in `basalt_meta` names catalog relations as `pg_catalog.<name>` and runs with `SET search_path = pg_catalog, pg_temp` ([version 24](#version-24-the-callers-temporary-tables-never-shadow-the-catalog)): `pg_temp` named last, so a temporary table or type the calling role created never resolves ahead of the catalog's. Where a section below says `SET search_path = pg_catalog`, the installed function has `pg_catalog, pg_temp`.
- Roles: `<prefix>_guard` (owner, `NOLOGIN`), `<prefix>_agents` (group, `NOLOGIN`), `<prefix>_agent_<name>` (one `LOGIN` role per agent). Default prefix `basalt`. They are cluster objects: uninstall drops them after the schema.
- **Schema versions.** The guard's first releases installed schema version 1, whose SQL is the files `001` to `011` of `internal/guard/schema/`, run in name order in one migration. The sections below headed "Version 2" to "Version 37", and the version numbers named elsewhere in this contract ("from version N", a guard "older than version N"), are the steps in which the guard was built before its first release: version 1 installs all of them, so every guard has every object they describe. Changes after the first release are schema versions from 2 on, each with its own section headed "Schema version N" and its own files, applied by `basalt upgrade` as above: [schema version 2](basalt-meta-schema-versions.md#schema-version-2-install-ids) (file `012`, breaking) and [schema version 3](basalt-meta-schema-versions.md#schema-version-3-plugin-events) (file `013`, non-breaking) and [schema version 4](basalt-meta-schema-versions.md#schema-version-4-plugin-trust-removed) (file `014`, non-breaking) and [schema version 5](basalt-meta-schema-versions.md#schema-version-5-plugin-approvals) (file `015`, non-breaking).

### Ledger tables and views

#### Tables and views (versions 1 to 3)

| Object | Purpose |
|---|---|
| `schema_version` | Installed migration versions |
| `guarded_tables` | Tables carrying the guard, with primary-key columns and reason `AGENT_WRITABLE` or `CASCADE_TARGET` |
| `runs` | One row per run: `run_id`, `task_id`, `agent`, `intent`, `started_at` |
| `changes` | The change record: one row per agent action (one top-level statement), `status` `APPLIED` or `REFUSED` in M1 |
| `ledger` | Append-only, hash-chained rows: `ROW_CHANGE` (old and new row, cascades included), `CHANGE` (statement, intent, duration), `REFUSED`, `RUN_STARTED`, `HEARTBEAT`, `DEAD_MAN`, `UNCOVERED_TABLES` (version 2), `PASSKEY_REVOKED` (version 12), `AGENT_SETUP` (version 16), `ENGINE_RECORDED` and `ENGINE_REVOKED` (version 33), `READ` (version 3: one per read, detail `runId`, `taskId`, `statement`, `tables`, `rows`, `durationMs`, `versions: [{table, key, version}]`), `PRUNED`. A `ROW_CHANGE` detail carries `xmin` (the version the write replaced), `cascaded`, and from version 3 `newXmin` (the version the write left: the writing transaction id, `null` for a delete; revert compares it, M3), `basedOn` (`{version, changeId}`) or `blindWrite` |
| `reads` | Version 3. A run's latest known version of each row it read or wrote: `(run_id, table_oid, row_key)` primary key, `row_version xid`, `change_id`, `at`. Removed with the run (1 year). The guard trigger compares it with `OLD.xmin` |
| `chain_head`, `chain_anchor` | Last appended `(seq, hash)`; where verification starts after retention deletes the oldest rows |
| `agent_guarded_tables` | Version 3. `table_oid`, `table_name`, `pk_cols` of guarded tables the calling agent can `SELECT`; the engine reads it to know which rows of a read it can identify |
| `agent_runs`, `agent_changes`, `agent_ledger`, `agent_guarded_tables` | With `schema_version` (version 13), `agent_setups` (version 16), `agent_engines` (version 33) and `agent_reinstalls` (version 36), the only objects an agent role can `SELECT`. Rows of the calling agent only; `agent_ledger` redacts key and values of tables the agent cannot `SELECT` (`redacted = true`) |

Chain: `hash_n = sha256(hash_{n-1} || canonical_n)` with `canonical_n` the `jsonb` text of the row's `seq`, `at` (epoch microseconds), `agent`, `changeId`, `kind`, `table`, `tableOid`, `op`, `key`, `valuesHash`, `depth` and `detail`, and `valuesHash = sha256(jsonb_build_array(old_row, new_row)::text)`. Retention nulls values after 30 days without breaking the chain and deletes ledger metadata after 1 year, moving the anchor.

#### Version 14: `list_runs` index

N12-R1. `runs_agent`, an index on `runs (agent, run_id)` for the per-agent keyset of `list_runs`.

### Functions an agent role may call

All `SECURITY DEFINER`, validating, and taking the agent from `session_user`, never from an argument.

| Function | Purpose |
|---|---|
| `start_run(run_id uuid, task_id uuid, intent text)` | Record a run |
| `finish_change(op text, statement text, params jsonb, duration_ms int) returns uuid` | Stamp the change the guard opened in this transaction (and chain a `CHANGE` ledger row with the statement and intent), or record a zero-row change with `op` |
| `record_refusal(run_id uuid, task_id uuid, intent text, op text, statement text, params jsonb, code text, reason text, duration_ms int) returns uuid` | A `REFUSED` change record |
| `record_event(kind text, run_id uuid, detail jsonb) returns bigint` | Engine events: `HEARTBEAT` (every hour; detail `engineVersion`, `chainBrokenAt` when the chain is broken, and `operatedBy` (`PERSON` or `AGENT`, CO-15)), `DEAD_MAN` (the engine checks in after more than 7 days of silence; detail `lastHeartbeat`, `silentHours`; D14), `UNCOVERED_TABLES` (detail `tables: [{table, why}]`, written when the set of unguarded tables changes). Version 2 adds the last two |
| `prune() returns jsonb` | Retention (30 days values, 1 year metadata) |
| `verify_chain() returns bigint` | First broken `seq`, or `NULL` when intact. The full check, from the anchor |
| `verify_chain_from(seq bigint, hash bytea) returns (broken_at bigint, seq bigint, hash bytea)` | Version 2. The incremental check: the row at `seq` (or the anchor) must still have `hash`, then every later row is recomputed up to the head. `broken_at` is the first broken `seq`, or `NULL` when intact; `(seq, hash)` is the head it verified, for the caller to keep. A pinned `seq` older than the anchor (retention deleted it) verifies from the anchor. `(0, zero hash)` is a full check |
| `chain_head() returns (seq, hash)`, `check_head(seq, hash) returns boolean` | Head pinning: the engine keeps the last head and checks it on start |
| `record_read(run_id uuid, statement text, params jsonb, tables text[], row_count int, duration_ms int, versions jsonb) returns uuid` | Version 3. A `SELECT` change record, a `READ` ledger row, and for a run the `reads` entries. `versions` is a JSON array (at most 10 000) of `{"tableOid": <oid>, "key": {<pk column>: value}, "version": "<xid>"}`; every table must be guarded and readable by the caller and every key must name exactly its primary-key columns. Called after the read's own read-only transaction |
| `uncovered_tables() returns (table_oid, why)` | Agent-writable tables and cascade targets without the guard |

### Approval objects

#### Version 4 (M2): approvals

Installed by the migration after M1.5's. Applying under `basalt.approval_id` is checked per row (approval of this agent and run, signed, unused, unexpired, no more rows than approved) and at commit (statement, parameters, row count and `rowsHash` of the recomputed lines); a match replaces the held `APPROVAL_PENDING` record with the applied one. `prune()` marks held writes past expiry `APPROVAL_EXPIRED`.

| Object | Purpose |
|---|---|
| `passkeys` | The person's passkeys: credential id, P-256 public key, RP ID, origin, signature counter. Written by `register_passkey` (admin only) |
| `approvals` | Held actions: statement, parameters, assigned columns, preview lines, `rows_hash`, binding text and hash, expiry, approval and use. Values pruned after 30 days |
| `agent_approvals` | The calling agent's approvals (status `PENDING`, `APPROVED`, `APPLIED`, `EXPIRED`) with binding text and lines |
| `agent_passkeys` | Registered passkeys' public data (credential id, label, public key, RP ID, origin, counter), so a relay can fill `credentialIds` and check a code locally before submitting |
| `preview_lines(assigned text[]) returns setof text` | Agent, in a `PREVIEW` transaction: the action's preview lines |
| `hold_action(statement text, params jsonb, assigned text[], lines text[]) returns (approval_id uuid, binding_text text, expires_at timestamptz)` | Agent: store the held action and its `APPROVAL_PENDING` change. Each line at most 64 KiB; from version 37 the lines together at most 64 MiB |
| `submit_approval(approval_id uuid, credential_id bytea, authenticator_data bytea, client_data_json bytea, signature bytea) returns timestamptz` | Any relay: verify the assertion, mark `APPROVED` |
| `register_passkey(credential_id bytea, x bytea, y bytea, rp_id text, origin text, label text)` | Admin: store a passkey (the point must be on P-256) |
| `_verify_assertion(binding bytea, credential_id bytea, authenticator_data bytea, client_data_json bytea, signature bytea)` | Internal, not granted to agents: the WebAuthn checks of `submit_approval` with challenge = `binding`, raising `BS005` `APPROVAL_INVALID` with a detail; bumps the passkey's counter. M3's `apply_revert` reuses it (and re-raises as `REVERT_INVALID`) |

`changes.status` gains `APPROVAL_PENDING` and `APPROVAL_EXPIRED`; ledger kinds `APPROVAL_PENDING` and `APPROVED`.

#### Version 37: held writes keep large lines

M4 (Large values, rule 7). Up to version 36 `hold_action` refused any preview line over 64 KiB with `BS008` `LEDGER_INPUT_INVALID`, so a held `DELETE` of a row with a large value was never held and the agent got `INTERNAL`. **Non-breaking** (AE-11): on an older guard the engine refuses such a write itself with `STATEMENT_REFUSED` `HOLD_TOO_LARGE`. Idempotent.

| Object | Change |
|---|---|
| `_check_held_lines(p_lines text[])` | New, internal (no grants). Refuses lines whose text, in bytes, sums to over 67 108 864 (64 MiB) with `BS007` `NOT_ALLOWED`, detail `HOLD_TOO_LARGE`, hint `the preview lines are <n> bytes; a held write holds at most 67108864` |
| `preview_lines` | Checks the cap before it returns a line, so the engine never reads more than a hold keeps |
| `hold_action` | No per-line cap; checks the cap before it parses a line. Otherwise as version 4 |

Both are replaced with `CREATE OR REPLACE`, `SECURITY DEFINER`, `SET search_path = pg_catalog, pg_temp`; owner and grants are kept. 64 MiB is far below Postgres's 1 GB limits on a value, an array and a protocol message, and above the [Large values](mcp-tools.md#large-values) example (a row with two values of 15 MB, escaped). The engine checks the same cap before it calls `hold_action`.

### Passkey objects

#### Version 12: passkey management

M4.1; see [Passkey management](passkey-management.md#passkey-management). It follows version 11, the agent RLS policy.

| Object | Purpose |
|---|---|
| `passkeys` | Gains `user_handle` (the WebAuthn user id the passkey was created with; null for passkeys registered before version 12), `last_used_at`, `revoked_at` and `revoked_by`. Rows are never deleted: a revoked passkey stays for the record |
| `_verify_assertion(...)` | Refuses a revoked passkey (`BS005` `APPROVAL_INVALID`, detail `passkey revoked`; `apply_revert` re-raises it as `REVERT_INVALID`), and sets `last_used_at` when it accepts an assertion |
| `register_passkey(credential_id bytea, x bytea, y bytea, rp_id text, origin text, label text, user_handle bytea)` | Replaces the six-argument form, which is dropped. Admin only. `user_handle` is 1 to 64 bytes or null. Refuses a revoked credential id (`BS008`): a removed passkey is registered again only as a new passkey |
| `revoke_passkey(credential_id bytea, force boolean) returns int` | Admin only, not granted to agents. Marks the passkey revoked and returns how many active passkeys remain. Refuses an unknown or already revoked id (`BS008`) and the last active passkey unless `force` (`BS007` `NOT_ALLOWED`). Appends a `PASSKEY_REVOKED` ledger row: `agent` the admin role, detail `credentialId` (base64url), `label`, `rpId`, `remaining`, `forced` |
| `agent_passkeys` | Active passkeys only (so approval and revert links list only those in `credentialIds`), and gains `created_at` and `last_used_at`. It keeps the public key, which a relay needs to check a code before submitting it |

### Row-level security policies

#### Version 8: row-level security

N12-7 and N12-8.

| Object | Purpose |
|---|---|
| Policy `<prefix>_guard` | `AS PERMISSIVE FOR ALL TO <prefix>_guard USING (true) WITH CHECK (true)` on every guarded table with RLS enabled, created by `attach` (every `basalt init`), dropped by `basalt uninstall`. Agent roles keep `NOBYPASSRLS`; they get a policy only as in version 11 |
| `uncovered_tables()` | Also returns guarded tables with RLS enabled and no guard policy, `why` = `RLS_WITHOUT_GUARD_POLICY` |
| Revert lines | Redacted on RLS tables as in [Revert](revert.md#lines-binding-and-codes) |

#### Version 11: agent RLS policy

Owner decision "Agent RLS" (Nov 12).

| Object | Purpose |
|---|---|
| Policy `<prefix>_agent_<name>` | `AS PERMISSIVE FOR SELECT TO <role> USING (true)` on a `--read` table, `FOR ALL ... USING (true) WITH CHECK (true)` on a `--write` table. Created by `basalt init` only on agent tables where RLS hid every row from the role and the person confirmed it (or passed `--agent-rls=all-rows`); kept on re-init; dropped by `basalt uninstall` |
| `record_agent_policy(agent name, table regclass, command text) returns bigint` | Admin only (init, after its `CREATE POLICY`): appends ledger kind `AGENT_POLICY_ADDED` for the agent (detail `policy`, `command` `SELECT` or `ALL`, `by`). Refuses a role that is not an agent or a table without that policy |

### PII objects

#### Version 15: PII classification

M5.1; see [PII classification](pii-classification.md#pii-classification). The M5.1 plan calls it version 14; 14 went to the `list_runs` index first. Forward-only, removed with `DROP SCHEMA basalt_meta CASCADE`. Breaking, the default (AE-11).

| Object | Shape and purpose |
|---|---|
| `pii_columns` | One row per classified column. `(table_schema text, table_name text, column_name text)` primary key; `data_type text` (as in [Readable columns](pii-classification.md#readable-columns-and-the-fingerprint)); `class text` (check: one of the five [classes](pii-classification.md#classes)); `entity_type text` (check: one of the five [entity types](pii-classification.md#entity-types), not null exactly when `class = 'IDENTIFIER'`); `suggested_class text`, `suggested_entity_type text` (same checks, between themselves; null when nothing was suggested); `reason text` (why it was suggested, names and counts only, never a value); `needs_review boolean not null default false`; `phone_region text` (check: `^[A-Z]{2}$`, null unless `entity_type = 'PHONE'`); `confirmed_at timestamptz`, `confirmed_by text` (`session_user` of the `basalt classify` run that confirmed the class; both null for a row of class `UNCLASSIFIED`). Written only by the admin (`basalt classify`) |
| `pii_catalog` | At most one row: `id boolean primary key default true check (id)`, `fingerprint bytea not null` (32 bytes, [the fingerprint](pii-classification.md#readable-columns-and-the-fingerprint) when `basalt classify` last wrote), `classified_at timestamptz not null`, `classified_by text not null`. Written only by the admin |
| `pii_readable_columns() returns table (table_oid oid, attnum smallint, table_schema text, table_name text, column_name text, data_type text)` | `SECURITY INVOKER`, `SET search_path = pg_catalog`: the [readable columns](pii-classification.md#readable-columns-and-the-fingerprint). The one definition `basalt classify` and `pii_fingerprint()` use. It reads only `pg_catalog` and calls `has_column_privilege` for the members of `<prefix>_agents`, which any role can already do, so it reveals nothing an agent could not query itself |
| `pii_fingerprint() returns bytea` | `SECURITY INVOKER`, `SET search_path = pg_catalog`, no arguments: the fingerprint of `pii_readable_columns()` now. Replaced in [version 19](#version-19-the-pii-fingerprint-names-columns-by-oid) |
| `agent_pii_columns` | View `WITH (security_barrier)`, owned by `<prefix>_guard` so it runs with that role's rights: `table_oid`, `attnum`, `table_schema`, `table_name`, `column_name`, `data_type` (as stored), `class`, `entity_type`, `phone_region`, `needs_review`, for the rows of `pii_columns` whose column exists under those names and that pass `has_column_privilege(session_user, table_oid, attnum, 'SELECT')` inside the view's own `WHERE`, so the filter runs before any function or operator of the caller's query. `table_oid` and `attnum` resolve the names through `pg_attribute`, so the engine maps a result column (pgx `FieldDescription.TableOID`, `TableAttributeNumber`) to its class without a second lookup |
| `agent_pii_catalog` | View `WITH (security_barrier)`, owned by `<prefix>_guard`: `fingerprint`, `classified_at` of `pii_catalog` (no row before the first `basalt classify`), filtered in the view's own `WHERE` to callers for whom `pg_has_role(session_user, '<prefix>_agents', 'USAGE')` holds |
| `pii_unclassified() returns table (table_schema text, table_name text, column_name text, data_type text, why text)` | `SECURITY INVOKER`: the columns the **login role** (`session_user`) may `SELECT`, with `USAGE` on their schema from version 27, by the readable-column rules, that need a person: `why` `NEW` (no row in `pii_columns`), `UNCLASSIFIED` (a row of that class) or `TYPE_CHANGED` (a row whose `data_type` differs from the column's type now; its class still applies). It reads classes through `agent_pii_columns`, so an agent needs no other grant. Ordered by schema, table, column (`COLLATE "C"`) |

**Writer.** `<prefix>_guard` owns `basalt_meta` and is `NOLOGIN`. `basalt classify` logs in with the admin connection string, which `basalt init` granted `<prefix>_guard` to, and runs its write transaction under `SET LOCAL ROLE <prefix>_guard` (as the migrations do); it reads the sample as the admin itself, outside that transaction.

**Grants.** `<prefix>_agents` gets `SELECT` on `agent_pii_columns` and `agent_pii_catalog`, and `EXECUTE` on `pii_unclassified()`, `pii_fingerprint()` and `pii_readable_columns()`; nothing else (`EXECUTE` on the functions is revoked from `PUBLIC`). An agent role can neither read nor write `pii_columns` and `pii_catalog`. Every agent-facing view added here is `WITH (security_barrier)` and filters on the login role (`session_user`) in its own `WHERE`, as the earlier `agent_*` views do. Not `current_user`: in a plain view it is the caller, but inside any `SECURITY DEFINER` function owned by `<prefix>_guard` that reads the view it would be `<prefix>_guard`, which may select every column, and after `SET ROLE` it is no longer the agent. `session_user` is the agent's login whatever runs the query, the identity the guard uses everywhere.

**Security tests** (required), run as the agent role:

- `SELECT`, `INSERT`, `UPDATE` and `DELETE` on `pii_columns` and `pii_catalog` are refused (`42501`); `INSERT`, `UPDATE` and `DELETE` on both views are refused.
- `agent_pii_columns` shows no row for a column the role cannot `SELECT` (a column of a table it has no grant on, and a column left out of a column-level grant on a table it can read in part).
- **Leaky function.** The role creates `pg_temp.leak(text, text, text) returns boolean`, cheap (`COST 0.0000001`), that raises a `NOTICE` with its arguments and returns true (`TEMP` is granted to `PUBLIC` by default), and runs `SELECT 1 FROM basalt_meta.agent_pii_columns WHERE pg_temp.leak(table_name, column_name, class)`. No notice names a column the role cannot select. For `agent_pii_catalog`, two runs of `SELECT 1 FROM basalt_meta.agent_pii_catalog WHERE pg_temp.leak(encode(fingerprint, 'hex'), classified_at::text, '')`: as the agent role (a member of `<prefix>_agents`, so the query reaches the filter and passes it) it sees exactly the one row; as a login role that is not a member, granted `SELECT` on the view for the test, it sees no notice and no row.

**Not covered here, open for M5.2.** Some `basalt_meta` agent views carry row values: `agent_changes` (`before`, `after`, `params`), `agent_ledger`, `agent_approvals` and `agent_reverts` (preview and revert lines), and the kept row versions. They are not readable columns of the person's tables, so they get no class here; M5.2 decides whether rule 2 refuses agent SQL on them or treats their values as PII.

#### Version 19: the PII fingerprint names columns by oid

Up to version 18 a fingerprint line was `schema.table.column:type`, unquoted and without the table's oid. A table dropped and created again with the same columns kept the fingerprint, so an engine keyed by oid and attribute number would keep the dead oid until it restarted; and a table `x.y` in `public` gave the same line as a table `y` in a schema `public.x`.

| Object | Purpose |
|---|---|
| `pii_fingerprint` | Replaced, same signature, still `SECURITY INVOKER` with `SET search_path = pg_catalog`, owned by `<prefix>_guard`, `EXECUTE` granted to `<prefix>_agents` and not to `PUBLIC`. Each line is now `format('%I.%I.%I:%s:%s:%s', table_schema, table_name, column_name, data_type, table_oid, attnum)`: see [the fingerprint](pii-classification.md#readable-columns-and-the-fingerprint) |

The fingerprint stored in `pii_catalog` is never compared with the live one, so it is not rewritten: the next `basalt classify` stores the new form.

#### Version 27: a PII column needs USAGE on its schema

Owner decision EV-14. Up to version 26 a column an agent role could `SELECT`, in a schema it had no `USAGE` on, was a readable column and listed by `pii_unclassified()`, though the role, and `basalt classify` scanning as it, got `permission denied for schema` reading it. **Breaking** (AE-11), the default. Idempotent.

| Object | Purpose |
|---|---|
| `pii_readable_columns` | Replaced, same signature, `SECURITY INVOKER`, `STABLE`, owner and grants as version 24's, `SET search_path = pg_catalog, pg_temp`. A column counts only when the member of `<prefix>_agents` that may `SELECT` it also has `USAGE` on its schema ([Readable columns](pii-classification.md#readable-columns-and-the-fingerprint)) |
| `pii_unclassified` | Replaced, same signature, `SECURITY INVOKER`, `STABLE`, owner and grants as version 15's, `SET search_path = pg_catalog, pg_temp`. Lists a column only when `session_user` has `USAGE` on its schema as well as `SELECT` on it |
| `pii_fingerprint` | Not replaced: it is built from `pii_readable_columns`, so a column without schema `USAGE` leaves it too. The fingerprint stored in `pii_catalog` is never compared with the live one, so nothing is rewritten |

### Setup objects

#### Version 16: setups

Planned, M4 ([Setup from your laptop](setup-from-laptop.md#setup-from-your-laptop), CO-13). Version 15 is taken by PII classification (M5.1); the two land in version order. Written only by the admin, inside the transaction of `basalt init --setup-code`.

| Object | Purpose |
|---|---|
| `setups` | One row per setup code that ran: `setup_id uuid` primary key (the code's UUIDv7, so a code runs once), `kind` (`INSTALL`, `AGENT`, `UPGRADE`), `agent_role name` (null for `UPGRADE`), `guard_version int` (the code's `guard.to`), `expires_at`, `used_at` (default `now()`), `used_by` (`session_user`). No agent role may write it |
| `agent_setups` | The calling agent role's rows of `setups` and every `UPGRADE` row: `setup_id`, `kind`, `guard_version`, `used_at`. The engine confirms a pending setup through it |
| `record_setup(setup_id uuid, kind text, agent name, guard_version int, expires_at timestamptz) returns bigint` | Admin only, not granted to agents. Records the setup and appends an `AGENT_SETUP` ledger row; returns its `seq`. `agent` is the agent role (null for `UPGRADE`, required otherwise; a role that is not a member of `<prefix>_agents` is `BS008`). Refuses, raising `BS010` with detail `USED` (the `setup_id` is recorded), `SUPERSEDED` (a later `setup_id` is recorded for the same role; not checked for `UPGRADE`), `EXPIRED` (`now()` at or past `expires_at`), `SETUP_ID_IN_FUTURE` (the UUIDv7 time of `setup_id`, its first 48 bits as milliseconds, more than 5 minutes after `now()`) or `EXPIRY_TOO_FAR` (`expires_at` more than 24 hours and 5 minutes after `now()`, or more than 24 hours after the `setup_id`'s time). The database's clock decides, not the code's. Replaced in [version 18](#version-18-record_setup-reads-the-clock-and-checks-the-role) |

Ledger kind `AGENT_SETUP`: `agent` the agent role (for `UPGRADE`, the admin role), detail `setupId`, `kind`, `guardVersion`, `by` (`session_user`). The install also gains one input in Go: the agent role's password given as a SCRAM-SHA-256 verifier instead of a generated one (format checked as in the [setup code](setup-from-laptop.md#the-setup-code), rendered as a SQL string literal).

#### Version 18: record_setup reads the clock and checks the role

Up to version 17 `record_setup` compared times with `now()`, which Postgres fixes when the transaction starts, so a code that expired while `basalt init --setup-code` waited in its transaction still ran; and it accepted any non-superuser member of `<prefix>_agents`.

| Object | Purpose |
|---|---|
| `record_setup` | Replaced, same signature, still `SECURITY DEFINER` with `SET search_path = pg_catalog`, owned by `<prefix>_guard` and executable by nobody else. The same as version 16's except: every time check uses `clock_timestamp()`, read after the setups lock (`EXPIRED`: `clock_timestamp()` at or past `expires_at`; `SETUP_ID_IN_FUTURE` and `EXPIRY_TOO_FAR` against the same reading); and `agent` must be a role that can log in (`rolcanlogin`), is not a superuser, has no `CREATEROLE`, is a member of `<prefix>_agents` (`USAGE`) and is not `<prefix>_agents` itself. Any other role is `BS008`: a superuser, a role that cannot log in, one with `CREATEROLE`, the group, a role outside it, a missing one |

### Hardening

#### Version 24: the caller's temporary tables never shadow the catalog

Up to version 23 every function in `basalt_meta` ran with `SET search_path = pg_catalog`, and some named catalog relations without a schema (`pg_roles`, `pg_class`, `pg_attribute`, `pg_index`, `pg_namespace`, `pg_constraint`, `pg_policy`, `pg_trigger`, `pg_auth_members`). Postgres searches the session's temporary schema for relations and types before `pg_catalog` unless `search_path` names `pg_temp`, so an agent role holding its own credential could create a temporary table `pg_roles` saying it is a superuser, grant `SELECT` on it to `PUBLIC`, and `guard_row` then skipped its writes: no intent, no approval, no ledger row. **Breaking** (AE-11), the default: an agent role can switch off the guard on an older one, so the engine serves it degraded (`GUARD_OUTDATED`) until `basalt upgrade` or an `UPGRADE` setup code applies this version. Idempotent.

| Object | Purpose |
|---|---|
| `_require_agent`, `guard_row`, `guard_truncate`, `_agent_writable`, `cascade_targets`, `attach`, `attach_all`, `uncovered_tables`, `_rls_applies`, `_revert_item`, `record_agent_policy`, `pii_readable_columns`, `record_setup` | Replaced, same signatures and behaviour, same `SECURITY DEFINER` or `INVOKER`, volatility, owner and grants as their latest version; every catalog relation is written `pg_catalog.<name>` |
| every function in `basalt_meta` | `search_path` set to `pg_catalog, pg_temp` (`ALTER FUNCTION`, over every function `pg_proc` lists in the schema) |

Revoking `TEMPORARY` on the database from `<prefix>_agents` is not part of it: Postgres grants `TEMPORARY` to `PUBLIC` by default, so a revoke from the group changes nothing while `PUBLIC` holds it, and revoking it from `PUBLIC` would change what the person's own roles and app may do.

#### Version 25: approval and revert deadlines read the wall clock

Up to version 24 every approval and revert deadline was compared with `now()`, which Postgres fixes when the transaction starts. An agent role that began a transaction before an approval's `expires_at`, a revert's `expires_at` or a signed batched revert's `apply_by` could keep it open past that time and still submit the signature, apply the write or revert, and commit; a fresh connection was already refused. **Breaking** (AE-11), the default: on an older guard an agent can still use a signature the person meant to be dead, so the engine serves it degraded (`GUARD_OUTDATED`) until `basalt upgrade` or an `UPGRADE` setup code applies this version. Idempotent.

| Object | Purpose |
|---|---|
| `submit_approval`, `_check_approval`, `_commit_approval`, `apply_revert`, `apply_revert_batch`, `_revert_lock_pending` | Replaced, same signatures, `SECURITY DEFINER`, owner and grants as their latest version, `SET search_path = pg_catalog, pg_temp`. Each deadline check reads `clock_timestamp()`, after the row lock where the function takes one: `APPROVAL_EXPIRED` once `expires_at` is at or before it, `REVERT_EXPIRED` likewise for a revert's `expires_at` and `apply_by`. `submit_approval` records that same reading as `approved_at` and returns it. `_check_approval` is now `VOLATILE` (it was `STABLE`) since it reads the clock. `_commit_approval` runs at commit, so a write under an approval that expired while its transaction was open fails at `COMMIT` and nothing lands. `_revert_lock_pending` is the check behind `rescope_revert`, `reset_revert` and `reject_revert`. A revert has no commit-time recheck, unlike an approval: `apply_revert` and `apply_revert_batch` write the rows inside the call, after the deadline check |

#### Version 26: guard triggers fire under any session_replication_role

Up to version 25 the guard's triggers were created the default way, `ENABLE`, which fires only when `session_replication_role` is `origin` or `local`. An agent role cannot set the parameter, and init resets the role's own settings, but a database default of `replica` (`ALTER DATABASE ... SET`, `ALTER ROLE ALL SET`, the server's configuration) reaches every new agent session, and the guard was skipped: no intent, no approval, no ledger row, no commit check. **Breaking** (AE-11), the default: on an older guard a database setting switches the guard off, so the engine serves it degraded (`GUARD_OUTDATED`) until `basalt upgrade` or an `UPGRADE` setup code applies this version. Idempotent. Setup also warns about the default itself: [Replication role default](cli.md#cli).

| Object | Purpose |
|---|---|
| `attach` | Replaced, same signature, `SECURITY INVOKER` with `SET search_path = pg_catalog, pg_temp`, owner and grants as version 24's. The same, plus `ALTER TABLE ... ENABLE ALWAYS TRIGGER basalt_guard, ENABLE ALWAYS TRIGGER basalt_guard_truncate` after creating them. It runs as the admin after every migration (`attach_all`), so an upgrade sets both triggers `ENABLE ALWAYS` on every table already guarded. `ALTER TABLE` needs the admin to own the table, as the policy and grants `attach` already sets do |
| `at_commit` on `basalt_meta.changes` | Set `ENABLE ALWAYS` |

#### Version 28: one clock for the person's acts, search_path on every routine

Up to version 27 `approved_at` (from version 25) read the wall clock, but `applied_at`, `signed_at` (with the `apply_by` window that starts at it) and `rejected_at` recorded `now()`, the transaction's start, which can be earlier than the deadline check that let the act through. Every time recorded for an act of the person now reads `clock_timestamp()`. Deadlines a function sets for later (`expires_at` of a held write or a prepared revert) still start at `now()`: a transaction that started earlier only shortens them. **Breaking** (AE-11), the default. Idempotent.

| Object | Purpose |
|---|---|
| `apply_revert`, `_revert_sign`, `_revert_finish`, `reject_revert` | Replaced, same signatures, `SECURITY DEFINER`, owner and grants as their latest version, `SET search_path = pg_catalog, pg_temp`. `apply_revert` and `_revert_finish` (the last batch) set `applied_at = clock_timestamp()`; `_revert_sign` sets `signed_at` and `apply_by = signed_at + 24 hours` from one reading; `reject_revert` reads `rejected_at` after locking the revert and returns that value as `rejectedAt` |
| every function and procedure in `basalt_meta` | `search_path` set to `pg_catalog, pg_temp` (`ALTER ROUTINE`, over `prokind` `f` and `p`; version 24's loop took `f` only) |

#### Version 34: the row trigger stores row images in fixed settings

`guard_row` builds the old and new row images with `to_jsonb`, which prints a `timestamptz` in the session's `TimeZone`, an `interval` in its `IntervalStyle`, a `float4` or `float8` by its `extra_float_digits` and `money` by its `lc_monetary`. The engine and `basalt revert` pin these in their own transactions ([Wire format](../CONTRACT.md#wire-format), Timestamps), but a write that skips the engine, the agent's credential used directly as in psql, ran the trigger in its own session's settings: its stored images, held lines and `rowsHash` differed from the engine's for the same rows, and a revert from the engine skipped its lines `CHANGED_AFTER`. **Non-breaking** (AE-11): on an older guard every write through the engine is pinned by the engine already, and only writes that skip it keep their session's form; the engine test that serves an agent on a guard without it covers the flag. Idempotent.

| Object | Purpose |
|---|---|
| `guard_row` | `ALTER FUNCTION ... SET TimeZone = 'UTC', DateStyle = 'ISO, MDY', IntervalStyle = 'postgres', extra_float_digits = 1, lc_monetary = 'C'` (one `SET` clause each), the values the engine pins. Body, `SECURITY DEFINER`, owner, grants and `search_path = pg_catalog, pg_temp` as version 24's. Postgres sets them when the trigger starts and restores the session's values when it returns, so they reach the trigger and the guard functions it calls and nothing else: the agent's own SQL in the same transaction, before and after the write, keeps its session's settings, including any it set with `SET LOCAL` or `set_config`. A later version that replaces `guard_row` restates these clauses, as it restates `search_path` |
| `guard_truncate`, `_at_commit` | Unchanged: they build no row image |

Rows a session in other settings stored before this version are not converted: as for the zone ([Wire format](../CONTRACT.md#wire-format), Timestamps), a line whose stored image no longer matches the row now is skipped `CHANGED_AFTER`, never written. A deleted row is restored from its stored image without that check, and its `money` values are now parsed in the C form: an image stored before this version in a database whose `lc_monetary` writes money otherwise (`1.234,50 €`) can fail to restore or restore a different amount. No guard with such rows has shipped.

#### Version 35: bytea_output and the revert functions

Two gaps version 34 left, both failing safe (lines skipped `CHANGED_AFTER`). `to_jsonb` prints a `bytea` column by the session's `bytea_output`, so a write that skipped the engine with `escape` stored `\000\377A` where the engine stores `\x00ff41`. And a revert reads the row now and restores the old values in its caller's settings: through the engine and `basalt revert` those are pinned, but a person calling `preview_revert`, `prepare_revert` or `apply_revert` by hand from another zone got the row now in that zone and every line skipped. **Non-breaking** (AE-11): on an older guard every call through the engine is pinned by the engine; the engine test that serves an agent on a guard without it covers the flag. Idempotent.

| Object | Purpose |
|---|---|
| `guard_row` | `ALTER FUNCTION ... SET bytea_output = 'hex'`, next to version 34's five clauses |
| `_revert_fetch`, `_revert_write` | `ALTER FUNCTION ... SET` the same six: `TimeZone = 'UTC'`, `DateStyle = 'ISO, MDY'`, `IntervalStyle = 'postgres'`, `extra_float_digits = 1`, `lc_monetary = 'C'`, `bytea_output = 'hex'`. Body, `SECURITY DEFINER`, owner, grants and `search_path` as their latest version's. `_revert_fetch` builds the row now that every conflict check and line compares; `_revert_write` parses the stored image back (`jsonb_populate_record`) and writes it, so the restore's own writes, cascades and the table's triggers run in these settings too, as they already do through the engine. Postgres restores the caller's values when each returns; `basalt.revert_target`, which `_revert_write` sets for the trigger, is not one of them and still reaches it |

A later version that replaces any of the three restates these clauses.

### Guard errors

Raised by the guard with SQLSTATE class `BS`. The tool code each maps to is in [Error codes](error-codes.md#error-codes), the only mapping table.

| SQLSTATE | Message | When |
|---|---|---|
| `BS001` | `INTENT_REQUIRED` | Agent write without `basalt.intent` |
| `BS002` | `APPROVAL_REQUIRED` | 11 to 50 rows, or any `DELETE`. without a signed approval (`basalt.approval_id`); the engine then previews and holds it |
| `BS003` | `ROW_LIMIT_EXCEEDED` | Over 50 rows in one action, cascades included |
| `BS004` | `STALE_READ` | An agent `UPDATE` or `DELETE` of a row whose `xmin` differs from the version in `reads` for the run in `basalt.run_id`. Detail names the table, key and both versions. Checked before the row policy |
| `BS005` | `APPROVAL_INVALID`, `APPROVAL_EXPIRED`, `REVERT_INVALID`, `REVERT_EXPIRED` | Bad approval, revert authorisation or signature; from schema version 5 also a plugin approval `submit_plugin_approval` refuses |
| `BS006` | `PREVIEW_CANNOT_COMMIT` | A preview transaction tried to commit |
| `BS007` | `NOT_ALLOWED` | `TRUNCATE`, unknown `basalt.mode`, a run of another agent; from version 37 a held write's preview lines over 64 MiB (detail `HOLD_TOO_LARGE`, the hint gives the size); from schema version 5 `open_plugin_approval` with detail `TOO_MANY_PENDING` or `UNKNOWN_AGENT` |
| `BS008` | `LEDGER_INPUT_INVALID` | A ledger function got invalid input; from schema version 3 also a plugin event outside the contract (`record_plugin_event`: an unknown kind or detail key, a wrong shape, or a detail over 4 KiB); from schema version 5 a plugin approval detail or settings outside the contract (`open_plugin_approval`) |
| `BS009` | `NOTHING_TO_REVERT`, `REVERT_CASCADE` | M3. A revert that cannot be prepared; `REVERT_CASCADE` is caught inside the revert and becomes a `CASCADE` conflict. `REVERT_TOO_LARGE` is removed in version 9 |
| `BS010` | `SETUP_REFUSED` | Planned, version 16. `record_setup` refused a setup code; detail `USED`, `SUPERSEDED`, `EXPIRED`, `SETUP_ID_IN_FUTURE` or `EXPIRY_TOO_FAR`. Raised to the admin's `basalt init --setup-code` only, never to an agent |
| `BS011` | `SCOPE_REFUSED` | Version 20. A revert scope descriptor refused by `preview_revert` or `prepare_revert`, and from version 21 `rescope_revert`. Shape details, from the descriptor alone: `SHAPE` (`INVALID_ARGUMENT`), `STORE_RESERVED` (`INVALID_ARGUMENT`), `FILTER_CAP` (`INVALID_ARGUMENT` `SCOPE_FILTER_CAP`). In `preview_revert` and `prepare_revert` (the agent's own proposal): `NOT_OWN_CHANGE`, `NOT_OWN_RUN`, `NOT_OWN_TASK` (the engine maps them to `NOT_FOUND` reason `CHANGE`, `RUN`, `TASK`, unknown and other agents' ids alike) and `FILTER` (`INVALID_ARGUMENT` `SCOPE_FILTER`; the message names each refused entry with the fixed texts of [MCP tools](mcp-tools.md#mcp-tools)). In `rescope_revert` a select that is not provably own work, or any select after a widen, is never answered with `BS011` before the proof or token check: it fails as `BS005` `REVERT_INVALID` detail `WIDEN_REFUSED`, one message for every cause; only a proven or own-work select gets `FILTER` or `DESCRIPTOR` (`INVALID_ARGUMENT`) for an agent, run or table outside the scope ([check order](revert.md#rescope-widen-and-reject)) |
