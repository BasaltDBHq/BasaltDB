## `basalt_meta`

- Everything BasaltDB installs lives in the `basalt_meta` schema and is removed with `DROP SCHEMA basalt_meta CASCADE`.
- The agent role has no direct `INSERT` on `basalt_meta` tables; ledger rows go through validating `SECURITY DEFINER` functions.
- Session settings use the `basalt.` prefix and are set transaction-local with `set_config(name, value, true)` (`SET LOCAL`), never session-level `SET`: `basalt.intent` (required on every agent write), `basalt.run_id`, `basalt.task_id`, `basalt.mode` (`APPLY` default, `PREVIEW`), `basalt.approval_id` (M2). The engine also sets `TimeZone`, `DateStyle`, `IntervalStyle`, `extra_float_digits`, `lc_monetary` and `bytea_output` this way in every transaction ([Wire format](../CONTRACT.md#wire-format), Timestamps), so row values print the same from any session; the guard's row trigger and the revert's row read and restore set them on themselves ([Row images in fixed settings](#row-images-in-fixed-settings)).
- Every BasaltDB connection to Postgres (engine and CLI) works through a transaction-mode pooler: it sends unnamed statements in one round trip (pgx `QueryExecModeExec`, `internal/platform/postgres/pgdial`), never named prepared statements, unless the connection string sets `default_query_exec_mode`.
- Schema changes to `basalt_meta` are forward-only and versioned; the installed version is recorded in `basalt_meta.schema_version`. Agent roles may `SELECT` it: the engine reads it on every agent tool call and compares the recorded versions with the ones its build installs (to an agent that cannot read the table every version is missing). AE-11: each migration is flagged **breaking** (the default) or **non-breaking**; marking one non-breaking needs a test that runs the engine against a guard without that migration. A missing breaking migration serves the agent degraded (`status` only, every other tool `UNAVAILABLE` `GUARD_OUTDATED` with the steps to the setup page's `UPDATE`, or, for a guard below the update floor ([An older install](setup-page.md#the-local-setup-page)), to remove it and set up again); missing only non-breaking ones serve normally with `GUARD_UPGRADE_AVAILABLE`. The engine checks again on each call, so a guard update needs no restart.
- Every function in `basalt_meta` names catalog relations as `pg_catalog.<name>` and runs with `SET search_path = pg_catalog, pg_temp` ([Catalog names and `search_path`](#catalog-names-and-search_path)): `pg_temp` named last, so a temporary table or type the calling role created never resolves ahead of the catalog's.
- Roles: `<prefix>_guard` (owner, `NOLOGIN`), `<prefix>_agents` (group, `NOLOGIN`), `<prefix>_agent_<name>` (one `LOGIN` role per agent). Default prefix `basalt`. They are cluster objects: uninstall drops them after the schema.
- **Schema versions.** Schema version 1 is the SQL files `001` to `011` of `internal/platform/postgres/guard/schema/`, run in name order in one migration. This file and the two that continue it ([basalt-meta-revert.md](basalt-meta-revert.md), [basalt-meta-installs.md](basalt-meta-installs.md)) describe what it installs, with one exception: [Reinstalls on the record](basalt-meta-installs.md#reinstalls-on-the-record) describes installs as schema version 2 leaves them (a random install id, `install_id()`), where schema version 1 used the oid of the `basalt_meta` schema. Changes after the first release are schema versions from 2 on, each with its own section and its own files, applied by the setup page's `UPDATE` ([Setup jobs](setup.md#setup-jobs)) as above: [schema version 2](basalt-meta-schema-versions.md#schema-version-2-install-ids) (file `012`, breaking), [schema version 3](basalt-meta-schema-versions.md#schema-version-3-plugin-events) (file `013`, non-breaking), [schema version 4](basalt-meta-schema-versions.md#schema-version-4-plugin-trust-removed) (file `014`, non-breaking) and [schema version 5](basalt-meta-schema-versions.md#schema-version-5-plugin-approvals) (file `015`, non-breaking). A new change takes the next schema version and a new section in [basalt-meta-schema-versions.md](basalt-meta-schema-versions.md).

### Step numbers from before the first release

Before its first release the guard was built in 37 numbered steps, each then called a version. Schema version 1 installs all of them, so every guard has every object they describe and no guard is "older than" one of them. The numbers are no longer versions of anything, but code comments, schema descriptions and a few sentences of this contract still name them ("basalt_meta version 20", "a guard older than version 33"). This table says where each step is described now.

| Steps | Described in |
|---|---|
| 1 to 3, 13, 14 | [Ledger tables and views](#ledger-tables-and-views), [Functions an agent role may call](#functions-an-agent-role-may-call) |
| 4, 37 | [Approval objects](#approval-objects) |
| 5 to 7, 9, 17 | [Revert objects](basalt-meta-revert.md#revert-objects) |
| 8, 11 | [Row-level security policies](#row-level-security-policies) |
| 12 | [Passkey objects](#passkey-objects) |
| 15, 19, 27 | [PII objects](#pii-objects) |
| 16, 18 | [Setup objects](#setup-objects) |
| 20 to 23, 32 | [Revert scope objects](basalt-meta-revert.md#revert-scope-objects) |
| 24 to 26, 28, 34, 35 | [Hardening](#hardening) |
| 29 to 31 | [Reveal objects](basalt-meta-revert.md#reveal-objects) |
| 33 | [Engine records](basalt-meta-installs.md#engine-records) |
| 36 | [Reinstalls on the record](basalt-meta-installs.md#reinstalls-on-the-record) |

Step 10 never had a section. Step 13 gave agent roles `SELECT` on `schema_version`.

### Ledger tables and views

| Object | Purpose |
|---|---|
| `schema_version` | Installed migration versions, with the BasaltDB release that wrote each from version 14 on (`release`) |
| `guarded_tables` | Tables carrying the guard, with primary-key columns and reason `AGENT_WRITABLE` or `CASCADE_TARGET` |
| `runs` | One row per run: `run_id`, `task_id`, `agent`, `intent`, `started_at`. Index `runs_agent` on `(agent, run_id)`, for the per-agent keyset of `list_runs` (N12-R1) |
| `changes` | The change record: one row per agent action (one top-level statement), `status` `APPLIED` or `REFUSED` in M1 |
| `ledger` | Append-only, hash-chained rows, each with the store-neutral fields from its first entry ([Ledger fields](#ledger-fields)): `ROW_CHANGE` (old and new row, cascades included), `CHANGE` (statement, intent, duration), `REFUSED`, `RUN_STARTED`, `HEARTBEAT`, `DEAD_MAN`, `UNCOVERED_TABLES`, `PASSKEY_REVOKED`, `AGENT_SETUP`, `ENGINE_RECORDED` and `ENGINE_REVOKED`, `TRUST_PIN_RECORDED` (schema version 6, [Schema version 6: trust pins](basalt-meta-schema-versions.md#schema-version-6-trust-pins)), `READ` (one per read, detail `runId`, `taskId`, `statement`, `resources`, `rows`, `durationMs`, `versions: [{resource, key, version}]`), `PRUNED`. A `ROW_CHANGE` detail carries `xmin` (the version the write replaced), `cascaded`, `newXmin` (the version the write left: the writing transaction id, `null` for a delete; revert compares it, M3), `basedOn` (`{version, changeId}`) or `blindWrite` |
| `reads` | A run's latest known version of each row it read or wrote: `(run_id, table_oid, row_key)` primary key, `row_version xid`, `change_id`, `at`. Removed with the run (1 year). The guard trigger compares it with `OLD.xmin` |
| `chain_head`, `chain_anchor` | Last appended `(seq, hash)`; where verification starts after retention deletes the oldest rows |
| `agent_guarded_tables` | `table_oid`, `table_name`, `pk_cols` of guarded tables the calling agent can `SELECT`; the engine reads it to know which rows of a read it can identify |
| `agent_runs`, `agent_changes`, `agent_ledger`, `agent_guarded_tables` | With `schema_version`, `agent_setups`, `agent_engines` and `agent_reinstalls`, the only objects an agent role can `SELECT`. Rows of the calling agent only; `agent_ledger` redacts key and values of tables the agent cannot `SELECT` (`redacted = true`) |

Chain: `hash_n = sha256(hash_{n-1} || canonical_n)` with `canonical_n` the `jsonb` text of the row's `seq`, `at` (epoch microseconds), `agent`, `changeId`, `kind`, `resource`, `tableOid`, `op`, `verb`, `key`, `valuesHash`, `depth` and `detail`, and `valuesHash = sha256(jsonb_build_array(old_row, new_row)::text)`. Retention nulls values after 30 days without breaking the chain and deletes ledger metadata after 1 year, moving the anchor.

#### Ledger fields

The ledger stores the [store-neutral form](stores.md#what-every-store-writes) from its first entry, with no mapping on read (clean state):

- **`op`** is Basalt's operation ([Operations](stores.md#operations)): `READ` for a read (never `SELECT`), `INSERT`, `UPDATE`, `DELETE`, `OTHER`, `REVERT`.
- **`verb`** is the store's own word for it ([Operations](stores.md#operations)): on a `ROW_CHANGE` row the word for that row's own `op` (in Postgres `INSERT`, `UPDATE` or `DELETE`, so a cascaded `SET NULL` row is `UPDATE`), on every other row the request's command, as `store.verb` in a [change record](change-record.md#the-change-record) (in Postgres `SELECT`, `INSERT`, `UPDATE`, `DELETE`, or the DDL command). A row with an `op` is `NULL` in exactly two cases ([Operations](stores.md#operations)): `REVERT`, and `OTHER` when the guard does not have the command. A row with no `op` has no `verb`.
- **`resource`** (was `table`) is what the row or action targets, in the store's form (`schema.table`). `tableOid` stays beside it, Postgres's own.
- **`agent`** stays the role (`session_user`), as in `runs.agent` and `reverts.requested_by`: the guard compares it with the session. Texts name the agent `agent:<name>` from the guard's record ([Agent names](stores.md#agent-names)).

The chain hashes `op`, `verb` and `resource`, so a row's operation and the store's word for it cannot change without breaking the chain.

### Functions an agent role may call

All `SECURITY DEFINER`, validating, and taking the agent from `session_user`, never from an argument.

| Function | Purpose |
|---|---|
| `start_run(run_id uuid, task_id uuid, intent text)` | Record a run |
| `finish_change(op text, statement text, params jsonb, duration_ms int) returns uuid` | Stamp the change the guard opened in this transaction (and chain a `CHANGE` ledger row with the statement and intent), or record a zero-row change with `op`. `op` is the request's own command, the `CHANGE` row's `verb` (an `INSERT … ON CONFLICT` whose rows all update has `op` `UPDATE` and `verb` `INSERT`) |
| `agent_name() returns text` | The caller's own name as texts write it, `agent:<name>` ([Agent names](stores.md#agent-names)); refuses a role with no recorded name (`BS007` `UNKNOWN_AGENT`) |
| `record_refusal(run_id uuid, task_id uuid, intent text, op text, statement text, params jsonb, code text, reason text, duration_ms int, resources text[]) returns uuid` | A `REFUSED` change record. `resources` (from [schema version 12](basalt-meta-schema-versions.md#schema-version-12-refusal-resources)) are the resources the refused statement names, qualified as for `record_read`: a write's target first (the first table it writes in statement order: a data-modifying `WITH` query's, as written, before the statement's own `INSERT`, `UPDATE`, `DELETE` or `MERGE` target), then the other names as the SQL check lists them; empty when it did not parse. The first 100 that are neither empty nor over 1000 bytes are kept, in order, and the rest left out: a refusal is always recorded, whatever its names. When the call fails with resources, the engine makes it once more with none and logs the first failure as a warning. The change record's `resource` is the first, the `REFUSED` ledger row's detail names them all as `resources`. From [schema version 13](basalt-meta-schema-versions.md#schema-version-13-refusal-cut-and-typed-not-found) an `intent` or `reason` over 2000 bytes and a `statement` over 64 KiB are cut to whole characters followed by `...`, at most the limit in all, on the change record and in the ledger row alike, and `params` over 64 KiB are recorded as `{"cut": true, "bytes": <size of the params as JSON text>}`; never refused for its size |
| `record_event(kind text, run_id uuid, detail jsonb) returns bigint` | Engine events: `HEARTBEAT` (every hour; detail `engineVersion`, `chainBrokenAt` when the chain is broken, and `operatedBy` (`PERSON` or `AGENT`, CO-15)), `DEAD_MAN` (the engine checks in after more than 7 days of silence; detail `lastHeartbeat`, `silentHours`; D14), `UNCOVERED_TABLES` (detail `tables: [{table, why}]`, written when the set of unguarded tables changes) |
| `prune() returns jsonb` | Retention (30 days values, 1 year metadata) |
| `verify_chain() returns bigint` | First broken `seq`, or `NULL` when intact. The full check, from the anchor |
| `verify_chain_from(seq bigint, hash bytea) returns (broken_at bigint, seq bigint, hash bytea)` | The incremental check: the row at `seq` (or the anchor) must still have `hash`, then every later row is recomputed up to the head. `broken_at` is the first broken `seq`, or `NULL` when intact; `(seq, hash)` is the head it verified, for the caller to keep. A pinned `seq` older than the anchor (retention deleted it) verifies from the anchor. `(0, zero hash)` is a full check |
| `chain_head() returns (seq, hash)`, `check_head(seq, hash) returns boolean` | Head pinning: the engine keeps the last head and checks it on start |
| `record_read(run_id uuid, statement text, params jsonb, tables text[], row_count int, duration_ms int, versions jsonb) returns uuid` | A `READ` change record (`store.verb` `SELECT`), a `READ` ledger row, and for a run the `reads` entries. `versions` is a JSON array (at most 10 000) of `{"tableOid": <oid>, "key": {<pk column>: value}, "version": "<xid>"}`; every table must be guarded and readable by the caller and every key must name exactly its primary-key columns. Called after the read's own read-only transaction. The engine passes `tables` as the ledger names a written table, `schema.table` with each part quoted where needed: it qualifies each name the statement wrote in the agent's own session (its `search_path`) in the same call, outside the function; a name already qualified is quoted as written, without a lookup, and one that resolves to nothing, or has more than two parts, is kept as written. In the order given, each once at its first place; the change record's `resource` is the first. Known limit: a quoted name holding a dot (`"public.payroll"`) is taken as `schema.table` |
| `uncovered_tables() returns (table_oid, why)` | Agent-writable tables and cascade targets without the guard, and guarded tables with RLS enabled and no guard policy, `why` = `RLS_WITHOUT_GUARD_POLICY` ([Row-level security policies](#row-level-security-policies)) |

### Approval objects

M2. Applying under `basalt.approval_id` is checked per row (approval of this agent and run, signed, unused, unexpired, no more rows than approved) and at commit (statement, parameters, row count and `rowsHash` of the recomputed lines); a match replaces the held `APPROVAL_PENDING` record with the applied one. `prune()` marks held writes past expiry `APPROVAL_EXPIRED`.

| Object | Purpose |
|---|---|
| `approvals` | Held actions: statement, parameters, assigned columns, preview lines, `rows_hash`, binding text and hash, expiry, approval and use. Values pruned after 30 days |
| `agent_approvals` | The calling agent's approvals (status `PENDING`, `APPROVED`, `APPLIED`, `EXPIRED`) with binding text and lines |
| `preview_lines(assigned text[]) returns setof text` | Agent, in a `PREVIEW` transaction: the action's preview lines. Checks the cap of `_check_held_lines` before it returns a line, so the engine never reads more than a hold keeps |
| `hold_action(op text, statement text, params jsonb, assigned text[], lines text[]) returns (approval_id uuid, binding_text text, expires_at timestamptz)` | Agent: store the held action and its `APPROVAL_PENDING` change. `op` is the request's own command (`INSERT`, `UPDATE` or `DELETE`), the ledger row's `verb`; `NULL` takes the first line's `op`, any other value is refused (`BS008`). No cap on one line; the lines together at most 64 MiB, checked with `_check_held_lines` before it parses a line |
| `_check_held_lines(p_lines text[])` | Internal (no grants). Refuses lines whose text, in bytes, sums to over 67 108 864 (64 MiB) with `BS007` `NOT_ALLOWED`, detail `HOLD_TOO_LARGE`, hint `the preview lines are <n> bytes; a held write holds at most 67108864` |
| `submit_approval(approval_id uuid, credential_id bytea, authenticator_data bytea, client_data_json bytea, signature bytea) returns timestamptz` | Any relay: verify the assertion, mark `APPROVED` |
| `_verify_assertion(binding bytea, credential_id bytea, authenticator_data bytea, client_data_json bytea, signature bytea)` | Internal, not granted to agents: the WebAuthn checks of `submit_approval` with challenge = `binding`, raising `BS005` `APPROVAL_INVALID` with a detail; bumps the passkey's counter and sets its `last_used_at`. Refuses a revoked passkey (detail `passkey revoked`). M3's `apply_revert` reuses it (and re-raises as `REVERT_INVALID`; from [schema version 11](basalt-meta-schema-versions.md#schema-version-11-typed-details) with detail `PASSKEY_REVOKED` for a revoked passkey) |

The passkeys themselves are under [Passkey objects](#passkey-objects). Every approval deadline reads the wall clock ([Deadlines and recorded times](#deadlines-and-recorded-times-read-the-wall-clock)).

`changes.status` also takes `APPROVAL_PENDING` and `APPROVAL_EXPIRED`; ledger kinds `APPROVAL_PENDING` and `APPROVED`.

**Large held lines** (M4, [Large values](mcp-tools.md#large-values), rule 7). A held `DELETE` of a row with a large value must still be held, so one line has no cap of its own. 64 MiB is far below Postgres's 1 GB limits on a value, an array and a protocol message, and above the [Large values](mcp-tools.md#large-values) example (a row with two values of 15 MB, escaped). The engine checks the same cap before it calls `hold_action`.

### Passkey objects

M4.1; see [Passkey management](passkey-management.md#passkey-management).

| Object | Purpose |
|---|---|
| `passkeys` | The person's passkeys: credential id, P-256 public key, RP ID, origin, signature counter, `user_handle` (the WebAuthn user id the passkey was created with; null when it was registered without one), `last_used_at`, `revoked_at` and `revoked_by`. Written by `register_passkey` (admin only). Rows are never deleted: a revoked passkey stays for the record |
| `register_passkey(credential_id bytea, x bytea, y bytea, rp_id text, origin text, label text, user_handle bytea)` | Admin only: store a passkey (the point must be on P-256). `user_handle` is 1 to 64 bytes or null. Refuses a revoked credential id (`BS008`): a removed passkey is registered again only as a new passkey |
| `revoke_passkey(credential_id bytea, force boolean) returns int` | Admin only, not granted to agents. Marks the passkey revoked and returns how many active passkeys remain. Refuses an unknown or already revoked id (`BS008`) and the last active passkey unless `force` (`BS007` `NOT_ALLOWED`). Appends a `PASSKEY_REVOKED` ledger row: `agent` the admin role, detail `credentialId` (base64url), `label`, `rpId`, `remaining`, `forced` |
| `agent_passkeys` | Active passkeys only (so approval and revert links list only those in `credentialIds`): their public data (credential id, label, public key, RP ID, origin, counter, `created_at`, `last_used_at`), so a relay can fill `credentialIds` and check a code locally before submitting |

### Row-level security policies

N12-7 and N12-8, and owner decision "Agent RLS" (Nov 12).

| Object | Purpose |
|---|---|
| Policy `<prefix>_guard` | `AS PERMISSIVE FOR ALL TO <prefix>_guard USING (true) WITH CHECK (true)` on every guarded table with RLS enabled, created by `attach` (every `basalt init`), dropped by the setup page's `REMOVE`. Agent roles keep `NOBYPASSRLS`; they get a policy only as in the next row |
| Policy `<prefix>_agent_<name>` | `AS PERMISSIVE FOR SELECT TO <role> USING (true)` on a read-only table, `FOR ALL ... USING (true) WITH CHECK (true)` on a read-write table. Created by the setup page only on agent tables where RLS hid every row from the role and the person left it checked (or listed it on the page); kept on re-init; dropped by the setup page's `REMOVE` |
| `record_agent_policy(agent name, table regclass, command text) returns bigint` | Admin only (init, after its `CREATE POLICY`): appends ledger kind `AGENT_POLICY_ADDED` for the agent (detail `policy`, `command` `SELECT` or `ALL`, `by`). Refuses a role that is not an agent or a table without that policy |
| `uncovered_tables()` | Also returns guarded tables with RLS enabled and no guard policy, `why` = `RLS_WITHOUT_GUARD_POLICY` |
| Revert lines | Redacted on RLS tables as in [Revert](revert.md#lines-binding-and-codes) |

### PII objects

M5.1; see [PII classification](pii-classification.md#pii-classification).

| Object | Shape and purpose |
|---|---|
| `pii_columns` | One row per classified column. `(table_schema text, table_name text, column_name text)` primary key; `data_type text` (as in [Readable columns](pii-classification.md#readable-columns-and-the-fingerprint)); `class text` (check: one of the five [classes](pii-classification.md#classes)); `entity_type text` (check: one of the five [entity types](pii-classification.md#entity-types), not null exactly when `class = 'IDENTIFIER'`); `suggested_class text`, `suggested_entity_type text` (same checks, between themselves; null when nothing was suggested); `reason text` (why it was suggested, names and counts only, never a value); `needs_review boolean not null default false`; `phone_region text` (check: `^[A-Z]{2}$`, null unless `entity_type = 'PHONE'`); `confirmed_at timestamptz`, `confirmed_by text` (`session_user` of the setup page's labels step that confirmed the class; both null for a row of class `UNCLASSIFIED`). Written only by the admin, through a setup page's labels step ([The Update check](setup-page.md#the-update-check), [Column labels on the connect page](connect.md#column-labels-on-the-connect-page)) |
| `pii_catalog` | At most one row: `id boolean primary key default true check (id)`, `fingerprint bytea not null` (32 bytes, [the fingerprint](pii-classification.md#readable-columns-and-the-fingerprint) when a setup page's labels step last wrote), `classified_at timestamptz not null`, `classified_by text not null`. Written only by the admin |
| `pii_readable_columns() returns table (table_oid oid, attnum smallint, table_schema text, table_name text, column_name text, data_type text)` | `SECURITY INVOKER`, `STABLE`: the [readable columns](pii-classification.md#readable-columns-and-the-fingerprint). A column counts only when the member of `<prefix>_agents` that may `SELECT` it also has `USAGE` on its schema (owner decision EV-14: without it the role gets `permission denied for schema` reading the column). The one definition the labels step and `pii_fingerprint()` use. It reads only `pg_catalog` and calls `has_column_privilege` for the members of `<prefix>_agents`, which any role can already do, so it reveals nothing an agent could not query itself |
| `pii_fingerprint() returns bytea` | `SECURITY INVOKER`, no arguments, `EXECUTE` granted to `<prefix>_agents` and not to `PUBLIC`: the fingerprint of `pii_readable_columns()` now. Each line is `format('%I.%I.%I:%s:%s:%s', table_schema, table_name, column_name, data_type, table_oid, attnum)`: see [the fingerprint](pii-classification.md#readable-columns-and-the-fingerprint). The line carries the table's oid and attribute number so that a table dropped and created again with the same columns changes the fingerprint, and an engine keyed by oid and attribute number does not keep the dead oid; the names are quoted so that a table `x.y` in `public` and a table `y` in a schema `public.x` give different lines. It is built from `pii_readable_columns`, so a column without schema `USAGE` leaves it too |
| `agent_pii_columns` | View `WITH (security_barrier)`, owned by `<prefix>_guard` so it runs with that role's rights: `table_oid`, `attnum`, `table_schema`, `table_name`, `column_name`, `data_type` (as stored), `class`, `entity_type`, `phone_region`, `needs_review`, for the rows of `pii_columns` whose column exists under those names and that pass `has_column_privilege(session_user, table_oid, attnum, 'SELECT')` inside the view's own `WHERE`, so the filter runs before any function or operator of the caller's query. `table_oid` and `attnum` resolve the names through `pg_attribute`, so the engine maps a result column (pgx `FieldDescription.TableOID`, `TableAttributeNumber`) to its class without a second lookup |
| `agent_pii_catalog` | View `WITH (security_barrier)`, owned by `<prefix>_guard`: `fingerprint`, `classified_at` of `pii_catalog` (no row before the first labels step that wrote), filtered in the view's own `WHERE` to callers for whom `pg_has_role(session_user, '<prefix>_agents', 'USAGE')` holds |
| `pii_unclassified() returns table (table_schema text, table_name text, column_name text, data_type text, why text)` | `SECURITY INVOKER`: the columns the **login role** (`session_user`) may `SELECT`, with `USAGE` on their schema, by the readable-column rules, that need a person: `why` `NEW` (no row in `pii_columns`), `UNCLASSIFIED` (a row of that class) or `TYPE_CHANGED` (a row whose `data_type` differs from the column's type now; its class still applies). It reads classes through `agent_pii_columns`, so an agent needs no other grant. Ordered by schema, table, column (`COLLATE "C"`) |

The fingerprint stored in `pii_catalog` is never compared with the live one: each labels step that writes stores the one it computed.

**Writer.** `<prefix>_guard` owns `basalt_meta` and is `NOLOGIN`. The setup page's labels step logs in with the admin connection string, which the install granted `<prefix>_guard` to, and runs its write transaction under `SET LOCAL ROLE <prefix>_guard` (as the migrations do); it reads the sample as the admin itself, outside that transaction. Planned: a setup run from the connect page writes the labels the person set the same way, inside the setup's transaction.

**Grants.** `<prefix>_agents` gets `SELECT` on `agent_pii_columns` and `agent_pii_catalog`, and `EXECUTE` on `pii_unclassified()`, `pii_fingerprint()` and `pii_readable_columns()`; nothing else (`EXECUTE` on the functions is revoked from `PUBLIC`). An agent role can neither read nor write `pii_columns` and `pii_catalog`. Every agent-facing view added here is `WITH (security_barrier)` and filters on the login role (`session_user`) in its own `WHERE`, as the earlier `agent_*` views do. Not `current_user`: in a plain view it is the caller, but inside any `SECURITY DEFINER` function owned by `<prefix>_guard` that reads the view it would be `<prefix>_guard`, which may select every column, and after `SET ROLE` it is no longer the agent. `session_user` is the agent's login whatever runs the query, the identity the guard uses everywhere.

**Security tests** (required), run as the agent role:

- `SELECT`, `INSERT`, `UPDATE` and `DELETE` on `pii_columns` and `pii_catalog` are refused (`42501`); `INSERT`, `UPDATE` and `DELETE` on both views are refused.
- `agent_pii_columns` shows no row for a column the role cannot `SELECT` (a column of a table it has no grant on, and a column left out of a column-level grant on a table it can read in part).
- **Leaky function.** The role creates `pg_temp.leak(text, text, text) returns boolean`, cheap (`COST 0.0000001`), that raises a `NOTICE` with its arguments and returns true (`TEMP` is granted to `PUBLIC` by default), and runs `SELECT 1 FROM basalt_meta.agent_pii_columns WHERE pg_temp.leak(table_name, column_name, class)`. No notice names a column the role cannot select. For `agent_pii_catalog`, two runs of `SELECT 1 FROM basalt_meta.agent_pii_catalog WHERE pg_temp.leak(encode(fingerprint, 'hex'), classified_at::text, '')`: as the agent role (a member of `<prefix>_agents`, so the query reaches the filter and passes it) it sees exactly the one row; as a login role that is not a member, granted `SELECT` on the view for the test, it sees no notice and no row.

**Not covered here, open for M5.2.** Some `basalt_meta` agent views carry row values: `agent_changes` (`before`, `after`, `params`), `agent_ledger`, `agent_approvals` and `agent_reverts` (preview and revert lines), and the kept row versions. They are not readable columns of the person's tables, so they get no class here; M5.2 decides whether rule 2 refuses agent SQL on them or treats their values as PII.

### Setup objects

Planned, M4 ([Setup](setup.md#setup), CO-13). Written only by the admin, inside the transaction of the setup the connect page runs.

| Object | Purpose |
|---|---|
| `setups` | One row per setup code that ran: `setup_id uuid` primary key (the code's UUIDv7, so a code runs once), `kind` (`INSTALL`, `AGENT`, `UPGRADE`), `agent_role name` (null for `UPGRADE`), `guard_version int` (the code's `guard.to`), `expires_at`, `used_at` (default `now()`), `used_by` (`session_user`). No agent role may write it |
| `agent_setups` | The calling agent role's rows of `setups` and every `UPGRADE` row: `setup_id`, `kind`, `guard_version`, `used_at`. The engine confirms a pending setup through it |
| `record_setup(setup_id uuid, kind text, agent name, guard_version int, expires_at timestamptz) returns bigint` | Admin only: `SECURITY DEFINER`, owned by `<prefix>_guard` and executable by nobody else. Records the setup and appends an `AGENT_SETUP` ledger row; returns its `seq`. `agent` is the agent role (null for `UPGRADE`, required otherwise). It must be a role that can log in (`rolcanlogin`), is not a superuser, has no `CREATEROLE`, is a member of `<prefix>_agents` (`USAGE`) and is not `<prefix>_agents` itself; any other role is `BS008`: a superuser, a role that cannot log in, one with `CREATEROLE`, the group, a role outside it, a missing one. Every time check uses one reading of `clock_timestamp()`, taken after the setups lock. Refuses, raising `BS010` with detail `USED` (the `setup_id` is recorded), `SUPERSEDED` (a later `setup_id` is recorded for the same role; not checked for `UPGRADE`), `EXPIRED` (it is more than 30 minutes after `expires_at`, the grace), `SETUP_ID_IN_FUTURE` (the UUIDv7 time of `setup_id`, its first 48 bits as milliseconds, more than 5 minutes after it) or `EXPIRY_TOO_FAR` (`expires_at` more than 10 minutes and 5 minutes after it, or more than 10 minutes after the `setup_id`'s time). Expiry has a 30-minute grace: opening and confirming a code need a live `expiresAt`, but a run that already passed those checks may finish up to 30 minutes after the code expires ([Valid for 10 minutes, single use (CO-13)](setup.md#the-setup-code)). The database's clock decides the remaining time checks, not the code's. It is the wall clock and not `now()`, which Postgres fixes when the transaction starts |

Ledger kind `AGENT_SETUP`: `agent` the agent role (for `UPGRADE`, the admin role), detail `setupId`, `kind`, `guardVersion`, `by` (`session_user`). The install also gains one input in Go: the agent role's password given as a SCRAM-SHA-256 verifier instead of a generated one (format checked as in the [setup code](setup.md#the-setup-code), rendered as a SQL string literal).

### Hardening

Rules that hold for every object in `basalt_meta`, each with the attack or fault it closes. A change that replaces one of the functions named here keeps its rule.

#### Catalog names and `search_path`

Every function and procedure in `basalt_meta` runs with `SET search_path = pg_catalog, pg_temp` and writes every catalog relation as `pg_catalog.<name>` (`pg_roles`, `pg_class`, `pg_attribute`, `pg_index`, `pg_namespace`, `pg_constraint`, `pg_policy`, `pg_trigger`, `pg_auth_members`). Postgres searches the session's temporary schema for relations and types before `pg_catalog` unless `search_path` names `pg_temp`. Without the rule an agent role holding its own credential could create a temporary table `pg_roles` saying it is a superuser, grant `SELECT` on it to `PUBLIC`, and `guard_row` would skip its writes: no intent, no approval, no ledger row. A function that runs after the agent's own statement in the same transaction (`reveal_approval_rows`) depends on it too.

Revoking `TEMPORARY` on the database from `<prefix>_agents` is not part of it: Postgres grants `TEMPORARY` to `PUBLIC` by default, so a revoke from the group changes nothing while `PUBLIC` holds it, and revoking it from `PUBLIC` would change what the person's own roles and app may do.

#### Deadlines and recorded times read the wall clock

Every approval and revert deadline is compared with `clock_timestamp()`, not `now()`, which Postgres fixes when the transaction starts. Otherwise an agent role that began a transaction before an approval's `expires_at`, a revert's `expires_at` or a signed batched revert's `apply_by` could keep it open past that time and still submit the signature, apply the write or revert, and commit, though a fresh connection would be refused.

| Object | Rule |
|---|---|
| `submit_approval`, `_check_approval`, `_commit_approval`, `apply_revert`, `apply_revert_batch`, `_revert_lock_pending` | Each deadline check reads `clock_timestamp()`, after the row lock where the function takes one: `APPROVAL_EXPIRED` once `expires_at` is at or before it, `REVERT_EXPIRED` likewise for a revert's `expires_at` and `apply_by`. `submit_approval` records that same reading as `approved_at` and returns it. `_check_approval` is `VOLATILE` since it reads the clock. `_commit_approval` runs at commit, so a write under an approval that expired while its transaction was open fails at `COMMIT` and nothing lands. `_revert_lock_pending` is the check behind `rescope_revert`, `reset_revert` and `reject_revert`. A revert has no commit-time recheck, unlike an approval: `apply_revert` and `apply_revert_batch` write the rows inside the call, after the deadline check |
| `apply_revert`, `_revert_sign`, `_revert_finish`, `reject_revert` | Every time recorded for an act of the person reads `clock_timestamp()`, so it is never earlier than the deadline check that let the act through. `apply_revert` and `_revert_finish` (the last batch) set `applied_at = clock_timestamp()`; `_revert_sign` sets `signed_at` and `apply_by = signed_at + 24 hours` from one reading; `reject_revert` reads `rejected_at` after locking the revert and returns that value as `rejectedAt` |

Deadlines a function sets for later (`expires_at` of a held write or a prepared revert) still start at `now()`: a transaction that started earlier only shortens them.

#### Guard triggers fire under any `session_replication_role`

A trigger created the default way, `ENABLE`, fires only when `session_replication_role` is `origin` or `local`. An agent role cannot set the parameter, and init resets the role's own settings, but a database default of `replica` (`ALTER DATABASE ... SET`, `ALTER ROLE ALL SET`, the server's configuration) reaches every new agent session and would skip the guard: no intent, no approval, no ledger row, no commit check. Setup also warns about the default itself: [Replication role default](cli.md#cli).

| Object | Rule |
|---|---|
| `attach` | `SECURITY INVOKER`. After creating the triggers it runs `ALTER TABLE ... ENABLE ALWAYS TRIGGER basalt_guard, ENABLE ALWAYS TRIGGER basalt_guard_truncate`. It runs as the admin after every migration (`attach_all`), so both triggers are `ENABLE ALWAYS` on every guarded table. `ALTER TABLE` needs the admin to own the table, as the policy and grants `attach` already sets do |
| `at_commit` on `basalt_meta.changes` | Set `ENABLE ALWAYS` |

#### Row images in fixed settings

`guard_row` builds the old and new row images with `to_jsonb`, which prints a `timestamptz` in the session's `TimeZone`, an `interval` in its `IntervalStyle`, a `float4` or `float8` by its `extra_float_digits`, `money` by its `lc_monetary` and a `bytea` by its `bytea_output` (with `escape`, `\000\377A` where the engine stores `\x00ff41`). The engine pins these in its own transactions ([Wire format](../CONTRACT.md#wire-format), Timestamps), but a write that skips the engine, the agent's credential used directly as in psql, runs the trigger in its own session's settings, and a person may call `preview_revert`, `prepare_revert` or `apply_revert` by hand from another zone. So the functions that build, read and restore row images set the values themselves. Without that, such a write's stored images, held lines and `rowsHash` would differ from the engine's for the same rows, and a revert would skip its lines `CHANGED_AFTER`.

| Object | Rule |
|---|---|
| `guard_row`, `_revert_fetch`, `_revert_write` | Each carries six `SET` clauses, the values the engine pins: `TimeZone = 'UTC'`, `DateStyle = 'ISO, MDY'`, `IntervalStyle = 'postgres'`, `extra_float_digits = 1`, `lc_monetary = 'C'`, `bytea_output = 'hex'`. Postgres sets them when the function starts and restores the caller's values when it returns, so they reach the function and the guard functions it calls and nothing else: the agent's own SQL in the same transaction, before and after the write, keeps its session's settings, including any it set with `SET LOCAL` or `set_config`. `_revert_fetch` builds the row now that every conflict check and line compares; `_revert_write` parses the stored image back (`jsonb_populate_record`) and writes it, so the restore's own writes, cascades and the table's triggers run in these settings too, as they already do through the engine. `basalt.revert_target`, which `_revert_write` sets for the trigger, is not one of the six and still reaches it |
| `guard_truncate`, `_at_commit` | No such clauses: they build no row image |

A schema version that replaces any of the three functions restates these clauses, as it restates `search_path`.

### Guard errors

Raised by the guard with SQLSTATE class `BS`. The tool code each maps to is in [Error codes](error-codes.md#error-codes), the only mapping table.

| SQLSTATE | Message | When |
|---|---|---|
| `BS001` | `INTENT_REQUIRED` | Agent write without `basalt.intent` |
| `BS002` | `APPROVAL_REQUIRED` | 11 to 50 rows, or any `DELETE`. without a signed approval (`basalt.approval_id`); the engine then previews and holds it |
| `BS003` | `ROW_LIMIT_EXCEEDED` | Over 50 rows in one action, cascades included |
| `BS004` | `STALE_READ` | An agent `UPDATE` or `DELETE` of a row whose `xmin` differs from the version in `reads` for the run in `basalt.run_id`. Detail names the table, key and both versions. Checked before the row policy |
| `BS005` | `APPROVAL_INVALID`, `APPROVAL_EXPIRED`, `REVERT_INVALID`, `REVERT_EXPIRED` | Bad approval, revert authorisation or signature; from schema version 5 also a plugin approval `submit_plugin_approval` refuses. `apply_revert`'s `REVERT_INVALID` from [schema version 11](basalt-meta-schema-versions.md#schema-version-11-typed-details) has a typed detail, the sentence as the hint: `ALREADY_APPLIED` and `ALREADY_SIGNED` (the engine's `ALREADY_SIGNED`), `PASSKEY_REVOKED`, `ROWS_CHANGED`; any other detail there is a refused signature. From [schema version 13](basalt-meta-schema-versions.md#schema-version-13-refusal-cut-and-typed-not-found) a revert the calling role did not prepare, or none, is `REVERT_INVALID` detail `NO_SUCH_REVERT`, the hint "no such revert", from every function that looks a revert up, and an approval it does not hold, or none, `APPROVAL_INVALID` detail `NO_SUCH_APPROVAL`, the hint "no such approval". The engine tells them apart by the detail alone, never by the words |
| `BS006` | `PREVIEW_CANNOT_COMMIT` | A preview transaction tried to commit |
| `BS007` | `NOT_ALLOWED` | `TRUNCATE`, unknown `basalt.mode`, a run of another agent; a held write's preview lines over 64 MiB (detail `HOLD_TOO_LARGE`, the hint gives the size); from schema version 5 `open_plugin_approval` with detail `TOO_MANY_PENDING` or `UNKNOWN_AGENT` |
| `BS008` | `LEDGER_INPUT_INVALID` | A ledger function got invalid input; from schema version 3 also a plugin event outside the contract (`record_plugin_event`: an unknown kind or detail key, a wrong shape, or a detail over 4 KiB); from schema version 5 a plugin approval detail or settings outside the contract (`open_plugin_approval`) |
| `BS009` | `NOTHING_TO_REVERT`, `REVERT_CASCADE` | M3. A revert that cannot be prepared; `REVERT_CASCADE` is caught inside the revert and becomes a `CASCADE` conflict. From [schema version 11](basalt-meta-schema-versions.md#schema-version-11-typed-details) a scope that changed no row a revert could restore has detail `READS_ONLY` (reason `READS_ONLY`), the hint naming the scope; every other `NOTHING_TO_REVERT` (every row would be skipped, or a signed revert with no row to restore) keeps its sentence as the detail. |
| `BS010` | `SETUP_REFUSED` | Planned. `record_setup` refused a setup code; detail `USED`, `SUPERSEDED`, `EXPIRED`, `SETUP_ID_IN_FUTURE` or `EXPIRY_TOO_FAR`. Raised to the person on the connect page only, never to an agent |
| `BS011` | `SCOPE_REFUSED` | A revert scope descriptor refused by `preview_revert`, `prepare_revert` or `rescope_revert`. Shape details, from the descriptor alone: `SHAPE` (`INVALID_ARGUMENT`; from [schema version 11](basalt-meta-schema-versions.md#schema-version-11-typed-details) a bad `agents`, `runs` or `resources` entry is named in the hint), `NAME` (from [schema version 9](basalt-meta-schema-versions.md#schema-version-9-revert-filter-name): a `resources` string entry that is not one `schema.table`; the hint names the first such entry in the caller's order, "`<entry>` is not a schema.table name", cut to 127 characters and `...`. In `preview_revert` and `prepare_revert` it is the agent's `resources` filter refused for its form: `INVALID_ARGUMENT` `SCOPE_FILTER` with that hint, never "not yours"; the engine tells it apart by the detail alone, never by the hint. In `rescope_revert` it is `INVALID_ARGUMENT` with the hint, like `SHAPE`. A guard below version 9 refuses such an entry as `SHAPE` with the hint `tables are schema.table names`, which the engine answers as any `SHAPE`), `STORE_RESERVED` (`INVALID_ARGUMENT`), `FILTER_CAP` (`INVALID_ARGUMENT` `SCOPE_FILTER_CAP`). In `preview_revert` and `prepare_revert` (the agent's own proposal): `NOT_OWN_CHANGE`, `NOT_OWN_RUN`, `NOT_OWN_TASK` (the engine maps them to `NOT_FOUND` reason `CHANGE`, `RUN`, `TASK`, unknown and other agents' ids alike) and `FILTER` (`INVALID_ARGUMENT` `SCOPE_FILTER`; the message names each refused entry with the fixed texts of [MCP tools](mcp-tools.md#mcp-tools)). In `rescope_revert` a select that is not provably own work, or any select after a widen, is never answered with `BS011` before the proof or token check: it fails as `BS005` `REVERT_INVALID` detail `WIDEN_REFUSED`, one message for every cause; only a proven or own-work select gets `FILTER` or `DESCRIPTOR` (`INVALID_ARGUMENT`) for an agent, run or table outside the scope ([check order](revert.md#rescope-widen-and-reject)) |
