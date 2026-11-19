## `basalt_meta`

- Everything BasaltDB installs lives in the `basalt_meta` schema and is removed with `DROP SCHEMA basalt_meta CASCADE`.
- The agent role has no direct `INSERT` on `basalt_meta` tables; ledger rows go through validating `SECURITY DEFINER` functions.
- Session settings use the `basalt.` prefix and are set transaction-local with `set_config(name, value, true)` (`SET LOCAL`), never session-level `SET`: `basalt.intent` (required on every agent write), `basalt.run_id`, `basalt.task_id`, `basalt.mode` (`APPLY` default, `PREVIEW`), `basalt.approval_id` (M2). The engine and `basalt revert` also set `TimeZone`, `DateStyle`, `IntervalStyle`, `extra_float_digits`, `lc_monetary` and `bytea_output` this way in every transaction ([Wire format](../CONTRACT.md#wire-format), Timestamps), so row values print the same from any session; the guard's row trigger and the revert's row read and restore set them on themselves (versions 34 and 35).
- Every BasaltDB connection to Postgres (engine and CLI) works through a transaction-mode pooler: it sends unnamed statements in one round trip (pgx `QueryExecModeExec`, `internal/pgdial`), never named prepared statements, unless the connection string sets `default_query_exec_mode`.
- Schema changes to `basalt_meta` are forward-only and versioned; the installed version is recorded in `basalt_meta.schema_version`. Agent roles may `SELECT` it: the engine reads it on every agent tool call and compares the recorded versions with the ones its build installs (to an agent that cannot read the table every version is missing). AE-11: each migration is flagged **breaking** (the default) or **non-breaking**; marking one non-breaking needs a test that runs the engine against a guard without that migration. A missing breaking migration serves the agent degraded (`status` only, every other tool `UNAVAILABLE` `GUARD_OUTDATED` with the `basalt upgrade` steps); missing only non-breaking ones serve normally with `GUARD_UPGRADE_AVAILABLE`. The engine checks again on each call, so `basalt upgrade` needs no restart.
- Every function in `basalt_meta` names catalog relations as `pg_catalog.<name>` and runs with `SET search_path = pg_catalog, pg_temp` ([version 24](#version-24-the-callers-temporary-tables-never-shadow-the-catalog)): `pg_temp` named last, so a temporary table or type the calling role created never resolves ahead of the catalog's. Where a section below says `SET search_path = pg_catalog`, the installed function has `pg_catalog, pg_temp`.
- Roles: `<prefix>_guard` (owner, `NOLOGIN`), `<prefix>_agents` (group, `NOLOGIN`), `<prefix>_agent_<name>` (one `LOGIN` role per agent). Default prefix `basalt`. They are cluster objects: uninstall drops them after the schema.
- **Schema versions.** The guard's first releases installed schema version 1, whose SQL is the files `001` to `011` of `internal/guard/schema/`, run in name order in one migration. The sections below headed "Version 2" to "Version 37", and the version numbers named elsewhere in this contract ("from version N", a guard "older than version N"), are the steps in which the guard was built before its first release: version 1 installs all of them, so every guard has every object they describe. Changes after the first release are schema versions from 2 on, each with its own section headed "Schema version N" and its own files, applied by `basalt upgrade` as above: [schema version 2](basalt-meta-versions-29-on.md#schema-version-2-install-ids) (file `012`, breaking) and [schema version 3](basalt-meta-versions-29-on.md#schema-version-3-plugin-events) (file `013`, non-breaking) and [schema version 4](basalt-meta-versions-29-on.md#schema-version-4-plugin-trust-removed) (file `014`, non-breaking) and [schema version 5](basalt-meta-versions-29-on.md#schema-version-5-plugin-approvals) (file `015`, non-breaking).

### Tables and views (versions 1 to 3)

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

### Version 4 (M2): approvals

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

### Versions 5 to 7 (M3): revert

Version 5 is the read-only plan, version 6 the trial run and prepared reverts, version 7 `apply_revert`.

| Object | Purpose |
|---|---|
| `ROW_CHANGE` detail | Gains `revertOf` on revert writes (`newXmin` landed in version 3) |
| `reverts` | Prepared reverts: scope, agents, intent, lines, `rows`, `skipped`, `rows_hash`, binding text and hash, 1-hour expiry, applying credential and change. Values pruned after 30 days |
| `revert_running` | Marks the transaction a revert or its trial runs in; written only by the revert functions |
| `agent_reverts` | The calling role's prepared reverts (status `PENDING`, `APPLIED`, `EXPIRED`) with binding text and lines |
| `preview_revert(scope text, scope_id uuid) returns setof text` | Agent: the revert lines, from a trial run that always rolls back. Needs a read-write transaction |
| `prepare_revert(scope text, scope_id uuid, intent text) returns (revert_id uuid, binding_text text, expires_at timestamptz, lines text[])` | Agent, as the CLI's relay: store the revert and its binding; returns the lines for the link (the sample, for a large plan). `NOTHING_TO_REVERT` |
| `apply_revert(revert_id uuid, credential_id bytea, authenticator_data bytea, client_data_json bytea, signature bytea) returns jsonb` | Any relay: verify the person's assertion and run the revert in the same transaction; returns `{changeId, rows, skipped}` |

`changes.op` gains `REVERT`; `changes.status` gains `REVERTED`; `changes` gains `actor_kind` (`AGENT`, `PERSON`), `revert_id`, `credential_id` and `reverted_by`, and `agent_changes` shows the last three; ledger kinds `REVERT_PENDING` and `REVERTED`. `<prefix>_guard` is granted `SELECT`, `INSERT`, `UPDATE`, `DELETE` on guarded tables, used only inside the revert functions. The guard trigger treats writes by `<prefix>_guard` during a revert as revert writes: no intent, no row limits, no `STALE_READ`, and no cascade into rows outside the revert (`BS009`).

### Version 8: row-level security

N12-7 and N12-8.

| Object | Purpose |
|---|---|
| Policy `<prefix>_guard` | `AS PERMISSIVE FOR ALL TO <prefix>_guard USING (true) WITH CHECK (true)` on every guarded table with RLS enabled, created by `attach` (every `basalt init`), dropped by `basalt uninstall`. Agent roles keep `NOBYPASSRLS`; they get a policy only as in version 11 |
| `uncovered_tables()` | Also returns guarded tables with RLS enabled and no guard policy, `why` = `RLS_WITHOUT_GUARD_POLICY` |
| Revert lines | Redacted on RLS tables as in [Revert](revert.md#lines-binding-and-codes) |

### Version 9: large reverts

N12-1 to N12-6.

| Object | Purpose |
|---|---|
| `reverts` | Gains `batched`, `sample_hash`, `covered` (the changes in scope at prepare), `signed_at`, `apply_by`, `batches` |
| `revert_lines` | A large plan's lines: number, text, the row's ledger chain, `outcome` (`PENDING`, `RESTORED`, `SKIPPED`), `conflict`, `sql_state`, `batch`. Text and chain pruned after 30 days |
| `agent_reverts` | Gains `batched`, `signed_at`, `apply_by`, `restored`, `skipped_now`, `pending`; status gains `APPLYING` |
| `agent_revert_lines` | The calling role's plan lines: `revert_id`, `line_no`, `line`, `outcome`, `conflict`, `sql_state`, `batch` |
| `apply_revert(...)` | For a large plan: verify the assertion and record the signature (`REVERT_SIGNED`); returns `{changeId, rows: 0, skipped, batched: true, pending, applyBy}` |
| `apply_revert_batch(revert_id uuid, lines int[]) returns jsonb` | The role that prepared the plan: apply up to 200 pending lines (see [Large plans](revert.md#large-plans)) |

Ledger kinds `REVERT_SIGNED` (detail `revertId`, `scope`, `scopeId`, `intent`, `credentialId`, `binding`, `lines`, `rows`, `skipped`, `applyBy`) and `REVERT_BATCH` (detail `revertId`, `batch`, `lines`, `rows`, `skipped`, `pending`); a large plan's `REVERTED` row carries `rows`, `skipped` (a count) and `batches`.

### Version 11: agent RLS policy

Owner decision "Agent RLS" (Nov 12).

| Object | Purpose |
|---|---|
| Policy `<prefix>_agent_<name>` | `AS PERMISSIVE FOR SELECT TO <role> USING (true)` on a `--read` table, `FOR ALL ... USING (true) WITH CHECK (true)` on a `--write` table. Created by `basalt init` only on agent tables where RLS hid every row from the role and the person confirmed it (or passed `--agent-rls=all-rows`); kept on re-init; dropped by `basalt uninstall` |
| `record_agent_policy(agent name, table regclass, command text) returns bigint` | Admin only (init, after its `CREATE POLICY`): appends ledger kind `AGENT_POLICY_ADDED` for the agent (detail `policy`, `command` `SELECT` or `ALL`, `by`). Refuses a role that is not an agent or a table without that policy |

### Version 12: passkey management

M4.1; see [Passkey management](passkey-management.md#passkey-management). It follows version 11, the agent RLS policy.

| Object | Purpose |
|---|---|
| `passkeys` | Gains `user_handle` (the WebAuthn user id the passkey was created with; null for passkeys registered before version 12), `last_used_at`, `revoked_at` and `revoked_by`. Rows are never deleted: a revoked passkey stays for the record |
| `_verify_assertion(...)` | Refuses a revoked passkey (`BS005` `APPROVAL_INVALID`, detail `passkey revoked`; `apply_revert` re-raises it as `REVERT_INVALID`), and sets `last_used_at` when it accepts an assertion |
| `register_passkey(credential_id bytea, x bytea, y bytea, rp_id text, origin text, label text, user_handle bytea)` | Replaces the six-argument form, which is dropped. Admin only. `user_handle` is 1 to 64 bytes or null. Refuses a revoked credential id (`BS008`): a removed passkey is registered again only as a new passkey |
| `revoke_passkey(credential_id bytea, force boolean) returns int` | Admin only, not granted to agents. Marks the passkey revoked and returns how many active passkeys remain. Refuses an unknown or already revoked id (`BS008`) and the last active passkey unless `force` (`BS007` `NOT_ALLOWED`). Appends a `PASSKEY_REVOKED` ledger row: `agent` the admin role, detail `credentialId` (base64url), `label`, `rpId`, `remaining`, `forced` |
| `agent_passkeys` | Active passkeys only (so approval and revert links list only those in `credentialIds`), and gains `created_at` and `last_used_at`. It keeps the public key, which a relay needs to check a code before submitting it |

### Version 14: `list_runs` index

N12-R1. `runs_agent`, an index on `runs (agent, run_id)` for the per-agent keyset of `list_runs`.

### Version 15: PII classification

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

### Version 16: setups

Planned, M4 ([Setup from your laptop](setup-from-laptop.md#setup-from-your-laptop), CO-13). Version 15 is taken by PII classification (M5.1); the two land in version order. Written only by the admin, inside the transaction of `basalt init --setup-code`.

| Object | Purpose |
|---|---|
| `setups` | One row per setup code that ran: `setup_id uuid` primary key (the code's UUIDv7, so a code runs once), `kind` (`INSTALL`, `AGENT`, `UPGRADE`), `agent_role name` (null for `UPGRADE`), `guard_version int` (the code's `guard.to`), `expires_at`, `used_at` (default `now()`), `used_by` (`session_user`). No agent role may write it |
| `agent_setups` | The calling agent role's rows of `setups` and every `UPGRADE` row: `setup_id`, `kind`, `guard_version`, `used_at`. The engine confirms a pending setup through it |
| `record_setup(setup_id uuid, kind text, agent name, guard_version int, expires_at timestamptz) returns bigint` | Admin only, not granted to agents. Records the setup and appends an `AGENT_SETUP` ledger row; returns its `seq`. `agent` is the agent role (null for `UPGRADE`, required otherwise; a role that is not a member of `<prefix>_agents` is `BS008`). Refuses, raising `BS010` with detail `USED` (the `setup_id` is recorded), `SUPERSEDED` (a later `setup_id` is recorded for the same role; not checked for `UPGRADE`), `EXPIRED` (`now()` at or past `expires_at`), `SETUP_ID_IN_FUTURE` (the UUIDv7 time of `setup_id`, its first 48 bits as milliseconds, more than 5 minutes after `now()`) or `EXPIRY_TOO_FAR` (`expires_at` more than 24 hours and 5 minutes after `now()`, or more than 24 hours after the `setup_id`'s time). The database's clock decides, not the code's. Replaced in [version 18](#version-18-record_setup-reads-the-clock-and-checks-the-role) |

Ledger kind `AGENT_SETUP`: `agent` the agent role (for `UPGRADE`, the admin role), detail `setupId`, `kind`, `guardVersion`, `by` (`session_user`). The install also gains one input in Go: the agent role's password given as a SCRAM-SHA-256 verifier instead of a generated one (format checked as in the [setup code](setup-from-laptop.md#the-setup-code), rendered as a SQL string literal).

### Version 17: a large plan's sample keeps restored rows

RSS-1 (amending N12-4). Up to version 16 a batched plan's sample was the first 1000 lines with `SKIP` lines first, so a plan with 1000 or more `SKIP` lines showed no `RESTORE` line.

| Object | Purpose |
|---|---|
| `_revert_sample(lines text[], max int) returns text[]` | Internal. The sample of [Large plans](revert.md#large-plans): up to `max / 2` lines of each kind, the other kind filling the rest, `SKIP` lines first, each kind in signed order. The same as `revert.Sample` in Go |
| `prepare_revert` | Replaced: the same as version 9's, with the sample from `_revert_sample` |

### Version 18: record_setup reads the clock and checks the role

Up to version 17 `record_setup` compared times with `now()`, which Postgres fixes when the transaction starts, so a code that expired while `basalt init --setup-code` waited in its transaction still ran; and it accepted any non-superuser member of `<prefix>_agents`.

| Object | Purpose |
|---|---|
| `record_setup` | Replaced, same signature, still `SECURITY DEFINER` with `SET search_path = pg_catalog`, owned by `<prefix>_guard` and executable by nobody else. The same as version 16's except: every time check uses `clock_timestamp()`, read after the setups lock (`EXPIRED`: `clock_timestamp()` at or past `expires_at`; `SETUP_ID_IN_FUTURE` and `EXPIRY_TOO_FAR` against the same reading); and `agent` must be a role that can log in (`rolcanlogin`), is not a superuser, has no `CREATEROLE`, is a member of `<prefix>_agents` (`USAGE`) and is not `<prefix>_agents` itself. Any other role is `BS008`: a superuser, a role that cannot log in, one with `CREATEROLE`, the group, a role outside it, a missing one |

### Version 19: the PII fingerprint names columns by oid

Up to version 18 a fingerprint line was `schema.table.column:type`, unquoted and without the table's oid. A table dropped and created again with the same columns kept the fingerprint, so an engine keyed by oid and attribute number would keep the dead oid until it restarted; and a table `x.y` in `public` gave the same line as a table `y` in a schema `public.x`.

| Object | Purpose |
|---|---|
| `pii_fingerprint` | Replaced, same signature, still `SECURITY INVOKER` with `SET search_path = pg_catalog`, owned by `<prefix>_guard`, `EXECUTE` granted to `<prefix>_agents` and not to `PUBLIC`. Each line is now `format('%I.%I.%I:%s:%s:%s', table_schema, table_name, column_name, data_type, table_oid, attnum)`: see [the fingerprint](pii-classification.md#readable-columns-and-the-fingerprint) |

The fingerprint stored in `pii_catalog` is never compared with the live one, so it is not rewritten: the next `basalt classify` stores the new form.

### Version 20: revert scope

Owner decisions RS-1 to RS-7. Version 20 is the `reverts` columns, `agent_reverts`, `preview_revert`, `prepare_revert`, `apply_revert` and `apply_revert_batch` rows below and the migration. `rescope_revert`, `reset_revert`, the `agent_revert_lines` redaction and their ledger kinds are [version 21](#version-21-widen-proof-rescope-and-reset); `reject_revert` is [version 23](#version-23-reject-a-revert). Version 19 is [the PII fingerprint by oid](#version-19-the-pii-fingerprint-names-columns-by-oid), already on master. If another change takes 20 first, this one takes the next free number. **Breaking** (AE-11): the engine calls functions with new signatures. Rules in [Revert](revert.md#revert): [The scope descriptor](revert.md#the-scope-descriptor) and [Rescope, widen and reject](revert.md#rescope-widen-and-reject).

| Object | Purpose |
|---|---|
| `reverts` | `selection jsonb NOT NULL` becomes the one source of the scope; `scope`, `scope_id` and `agents` become generated columns (`GENERATED ALWAYS AS (…) STORED`, the agents array through an `IMMUTABLE` helper), so they cannot disagree with it and existing indexes and views keep working. New: `proposed jsonb NOT NULL`; `widened boolean NOT NULL GENERATED ALWAYS AS (_widened(selection, requested_by)) STORED` (true when `selection->'agents'` is `null` or names a role other than `requested_by`); `ceiling jsonb` (the widest proven select); `scope_token_hash bytea`; `rescope_nonce bytea NOT NULL` (16 random bytes); `rescoped int NOT NULL DEFAULT 0`; `rejected_at timestamptz`, `reject_note text`; `CHECK ((ceiling IS NULL) = (scope_token_hash IS NULL))`. "Inside the requester's own work" needs the ledger, so the functions that write `selection` test it, not a `CHECK` |
| `agent_reverts` | Status gains `REJECTED`; gains `selection`, `widened`, `rejected_at`, `reject_note`. For a widened revert `binding_text`, `selection` and `lines` are `NULL` |
| `preview_revert(p_select jsonb) returns setof text` | Replaces `(scope text, scope_id uuid)`. For an agent role, own work only: `agents` exactly `[session_user]`, the change or run its own or a task it ran in, `runs` and `tables` inside that work, at most 20 each, no `store`. Normalizes the descriptor, then plans as before |
| `prepare_revert(p_select jsonb, p_intent text)` | Replaces `(scope text, scope_id uuid, intent text)`, same result columns. Own work only, as `preview_revert`. Stores `selection = proposed = p_select` (normalized) and a fresh nonce, and builds the binding from the stored row. For a `TASK` the caller ran in, an own proposal with no lines is stored instead of `NOTHING_TO_REVERT` (it cannot be signed until widened); the MCP tools never store one, they answer `NOTHING_TO_REVERT` |
| `apply_revert`, `apply_revert_batch` | Lock the revert row before checking; recompute or check lines from the stored `selection`; `apply_revert` refuses (`REVERT_INVALID`) a binding whose `select` is not the stored `selection`, and a `REJECTED` revert |


**Migration.** Every existing revert gets `selection` from its `scope`, `scope_id` and `agents` (`runs` and `tables` `null`), `proposed = selection` and a nonce; then the old columns become the generated ones and the views that use them are recreated. Reverts from the M3-14 era whose `agents` name other roles come out `widened`. Every `PENDING` revert with no signature gets `expires_at = now()` (its old binding has no `select`); when there was any, a `MIGRATION` ledger row notes the count (detail `version: 20`, `revertsExpired`). Like every migration from version 16, it is idempotent. A large plan signed before the upgrade (`APPLYING`, within its 24 hours) keeps its numbered lines and old binding and finishes as signed: `apply_revert_batch` checks each line against its stored signed text, not the binding's `select`. An engine on an older guard answers `UNAVAILABLE` `GUARD_OUTDATED`; the upgrade is `basalt upgrade` or an `UPGRADE` setup code.

### Version 21: widen proof, rescope and reset

Owner decisions RS-2 and RS-5. Rules in [Rescope, widen and reject](revert.md#rescope-widen-and-reject). Version 20 already adds the `reverts` columns these use (`proposed`, `ceiling`, `scope_token_hash`, `rescope_nonce`, `rescoped`). **Breaking** (AE-11), the default. Like every migration from version 16, it is idempotent.

| Object | Purpose |
|---|---|
| `rescope_revert(p_revert_id uuid, p_select jsonb, p_proof jsonb, p_rescope_key bytea, p_token bytea) returns jsonb` | New. Shape first (`BS011` `SHAPE`, `STORE_RESERVED`, `FILTER_CAP`, from `p_select` alone). Then locks the revert row (`FOR UPDATE`); only a `PENDING`, unsigned, unexpired revert prepared by `session_user` (another role's revert reads like an unknown id: `REVERT_INVALID` "no such revert"). Then, in the [check order](revert.md#rescope-widen-and-reject): with `p_proof` (`{credentialId, authenticatorData, clientDataJson, signature}`, base64url), the proof must verify (`_verify_assertion`; any error while checking it counts as a bad proof) over the widen challenge with the current `rescope_nonce` and `p_rescope_key` (32 bytes); the nonce is then replaced, the select becomes the ceiling and a new scope token is returned (only `sha256` of it is stored). Without a proof: own work while the revert has no ceiling; once it has one, `p_token` whose `sha256` is `scope_token_hash` and a select inside the ceiling (the same scope; `agents`, `runs`, `tables` each a subset of the ceiling's, any when the ceiling's is `null`). Every failure there is `BS005` `REVERT_INVALID` detail `WIDEN_REFUSED` with one fixed hint. Then scope membership: the scope is the proposal's, or the run or task the proposal's change or run belongs to, and each listed agent other than the requester has a change in it (`BS011` `DESCRIPTOR`); each listed run is a run of the task by a selected agent and each listed table was written in the scope by them (`BS011` `FILTER`). Rebuilds the lines as `prepare_revert` does (a `TASK` with no line is stored empty; any other scope with nothing to restore is `NOTHING_TO_REVERT`); replaces `selection`, lines, totals, `rows_hash`, binding and expiry (one hour from now); keeps `proposed`; `rescoped + 1`; appends `REVERT_RESCOPED`. Returns `{revertId, binding, expiresAt, lines, rescopeNonce}` (`lines` is a large plan's sample), plus `catalog` ([`revert-scope-response.schema.json`](../api/mcp/revert/revert-scope-response.schema.json), computed from the ceiling) for a proven or token-bearing call and `scopeToken` (16 bytes, base64url) for a proven one |
| `reset_revert(p_revert_id uuid) returns jsonb` | New, for the agent's `reissueLink`. Locks the row; only a `PENDING`, unsigned, unexpired revert prepared by `session_user`. Back to `proposed`: lines rebuilt, ceiling and token cleared, new nonce, new binding and expiry; appends `REVERT_RESET`. Needs no token: it only ever narrows to the agent's own proposal (owner, Q8). Returns `{revertId, binding, expiresAt, lines, rescopeNonce}` |
| `preview_revert`, `prepare_revert` | The change of a widened revert (its `op: REVERT` change, recorded under the relaying role) is not the role's own: `BS011` `NOT_OWN_CHANGE`, the same text as an unknown change, so an agent cannot preview or request an undo that would show it the rows and old values the person added (RS-5). Undoing a revert of the agent's own work is unchanged (AE-14) |
| `agent_revert_lines` | For a widened revert, `line` is `NULL` unless every change the line names (its `changeIds`) is the requesting role's. Line numbers, `outcome`, `conflict`, `sql_state` and `batch` stay, so the agent can still apply a signed plan's batches |
| `agent_ledger` | Redacts what a widened revert names of other agents' work. A row whose detail names a `revertId` (`REVERT_PENDING`, `REVERT_SIGNED`, `REVERT_BATCH`, `REVERTED`, `REVERT_RESCOPED`, `REVERT_RESET`) shows `detail` as `{revertId, widened: true, via}` only (`via` when the row has one) when that revert is widened now, or when the row's `select`, `oldSelect` or `droppedSelect` covers changes not made by the row's agent: their `skipped` lists copy the skipped lines' tables and keys, and the selects name other roles and runs. A `ROW_CHANGE` written by the change of a widened revert, for a row whose reverted changes (`revertOf`) are not all the row's agent's, shows no `table_name`, `row_key`, `old_row` or `new_row`, `detail` `{widened: true}`, and `redacted = true` |
| `changes` | Index `changes_task_agent (task_id, agent, change_id)`: an agent's task proposal is looked up by task and agent, so its cost does not grow with other agents' changes in the task |

All new functions are `SECURITY DEFINER` with `SET search_path = pg_catalog`, owned by `<prefix>_guard`; `EXECUTE` on `rescope_revert` and `reset_revert` is granted to `<prefix>_agents` only, and no function in `basalt_meta` is executable by `PUBLIC`. The link secret never reaches Postgres: `rescope_revert` takes only the key the engine derives from it, and records only its `sha256`.

Ledger kinds `REVERT_RESCOPED` (detail `revertId`, `oldSelect`, `select`, `oldRowsHash`, `rowsHash`, `via` the path Postgres checked: `OWN_WORK` (no proof or token: the person on the link, the agent holding it, or the agent role directly, which Postgres cannot tell apart), `PROOF` (with `credentialId` as lowercase hex and `rescopeKeyHash` = hex `sha256(rescopeKey)`) or `SCOPE_TOKEN`; never a key, secret or token) and `REVERT_RESET` (`revertId`, `droppedSelect`, `oldRowsHash`, `rowsHash`; always the requesting role).

### Version 22: the rescope nonce

Owner decision RS-2. The engine serves the revert's `rescopeNonce` on `GET /api/v1/reverts/{revertId}` at any time, an engine restart included, so the page can always ask the person for a widen proof. **Breaking** (AE-11), the default: the engine calls the new function. Idempotent.

| Object | Purpose |
|---|---|
| `revert_nonce(p_revert_id uuid) returns bytea` | New. The `rescope_nonce` of a revert prepared by `session_user`; another role's revert or an unknown id is `REVERT_INVALID` "no such revert", alike. `SECURITY DEFINER`, `SET search_path = pg_catalog`, `EXECUTE` for `<prefix>_agents` only, none for `PUBLIC`. The nonce is worthless without the person's passkey and the page's new link secret, and the role could already read it from an own-work `rescope_revert` |

### Version 23: reject a revert

Owner decisions RS-2 and Q8 ("agent can propose, human can agree, rescope, or reject"). Rules in [Rescope, widen and reject](revert.md#rescope-widen-and-reject). Version 20 already adds the `reverts` columns (`rejected_at`, `reject_note` with its 500-character check) and `REJECTED` in `agent_reverts`; `apply_revert`, `rescope_revert` and `reset_revert` already refuse a `REJECTED` revert. **Breaking** (AE-11), the default: the engine calls the new function. Idempotent.

| Object | Purpose |
|---|---|
| `reject_revert(p_revert_id uuid, p_note text, p_token bytea) returns jsonb` | New. The note first, from `p_note` alone: `NULL` or `''` for none, at most 500 characters (`BS008` `LEDGER_INPUT_INVALID` otherwise). Then locks the revert row (`FOR UPDATE`); only a `PENDING`, unsigned, unexpired revert prepared by `session_user` (another role's revert reads like an unknown id: `REVERT_INVALID` "no such revert"; an applied, signed or rejected one is `REVERT_INVALID`, an expired one `REVERT_EXPIRED`). Then the token: while the revert has no ceiling, `p_token` must be `NULL`; once it has one, `p_token` must be its scope token. Every token failure is `REVERT_INVALID` detail `WIDEN_REFUSED` with the one fixed hint of `rescope_revert`. Sets `rejected_at` and `reject_note`, appends `REVERT_REJECTED`. Returns `{revertId, status: "REJECTED", rejectedAt}`. `SECURITY DEFINER`, `SET search_path = pg_catalog`, `EXECUTE` for `<prefix>_agents` only, none for `PUBLIC` |

Ledger kind `REVERT_REJECTED` (detail `revertId`, `note` when there is one, `via`: `LINK_OR_AGENT` without a token, `SCOPE_TOKEN` with one; never the token). For a widened revert `agent_ledger` shows the requesting role only `{revertId, widened: true, via}`, as for every revert row (version 21); the note reaches the agent through `agent_reverts.reject_note` and the wait form.

### Version 24: the caller's temporary tables never shadow the catalog

Up to version 23 every function in `basalt_meta` ran with `SET search_path = pg_catalog`, and some named catalog relations without a schema (`pg_roles`, `pg_class`, `pg_attribute`, `pg_index`, `pg_namespace`, `pg_constraint`, `pg_policy`, `pg_trigger`, `pg_auth_members`). Postgres searches the session's temporary schema for relations and types before `pg_catalog` unless `search_path` names `pg_temp`, so an agent role holding its own credential could create a temporary table `pg_roles` saying it is a superuser, grant `SELECT` on it to `PUBLIC`, and `guard_row` then skipped its writes: no intent, no approval, no ledger row. **Breaking** (AE-11), the default: an agent role can switch off the guard on an older one, so the engine serves it degraded (`GUARD_OUTDATED`) until `basalt upgrade` or an `UPGRADE` setup code applies this version. Idempotent.

| Object | Purpose |
|---|---|
| `_require_agent`, `guard_row`, `guard_truncate`, `_agent_writable`, `cascade_targets`, `attach`, `attach_all`, `uncovered_tables`, `_rls_applies`, `_revert_item`, `record_agent_policy`, `pii_readable_columns`, `record_setup` | Replaced, same signatures and behaviour, same `SECURITY DEFINER` or `INVOKER`, volatility, owner and grants as their latest version; every catalog relation is written `pg_catalog.<name>` |
| every function in `basalt_meta` | `search_path` set to `pg_catalog, pg_temp` (`ALTER FUNCTION`, over every function `pg_proc` lists in the schema) |

Revoking `TEMPORARY` on the database from `<prefix>_agents` is not part of it: Postgres grants `TEMPORARY` to `PUBLIC` by default, so a revoke from the group changes nothing while `PUBLIC` holds it, and revoking it from `PUBLIC` would change what the person's own roles and app may do.

### Version 25: approval and revert deadlines read the wall clock

Up to version 24 every approval and revert deadline was compared with `now()`, which Postgres fixes when the transaction starts. An agent role that began a transaction before an approval's `expires_at`, a revert's `expires_at` or a signed batched revert's `apply_by` could keep it open past that time and still submit the signature, apply the write or revert, and commit; a fresh connection was already refused. **Breaking** (AE-11), the default: on an older guard an agent can still use a signature the person meant to be dead, so the engine serves it degraded (`GUARD_OUTDATED`) until `basalt upgrade` or an `UPGRADE` setup code applies this version. Idempotent.

| Object | Purpose |
|---|---|
| `submit_approval`, `_check_approval`, `_commit_approval`, `apply_revert`, `apply_revert_batch`, `_revert_lock_pending` | Replaced, same signatures, `SECURITY DEFINER`, owner and grants as their latest version, `SET search_path = pg_catalog, pg_temp`. Each deadline check reads `clock_timestamp()`, after the row lock where the function takes one: `APPROVAL_EXPIRED` once `expires_at` is at or before it, `REVERT_EXPIRED` likewise for a revert's `expires_at` and `apply_by`. `submit_approval` records that same reading as `approved_at` and returns it. `_check_approval` is now `VOLATILE` (it was `STABLE`) since it reads the clock. `_commit_approval` runs at commit, so a write under an approval that expired while its transaction was open fails at `COMMIT` and nothing lands. `_revert_lock_pending` is the check behind `rescope_revert`, `reset_revert` and `reject_revert`. A revert has no commit-time recheck, unlike an approval: `apply_revert` and `apply_revert_batch` write the rows inside the call, after the deadline check |

### Version 26: guard triggers fire under any session_replication_role

Up to version 25 the guard's triggers were created the default way, `ENABLE`, which fires only when `session_replication_role` is `origin` or `local`. An agent role cannot set the parameter, and init resets the role's own settings, but a database default of `replica` (`ALTER DATABASE ... SET`, `ALTER ROLE ALL SET`, the server's configuration) reaches every new agent session, and the guard was skipped: no intent, no approval, no ledger row, no commit check. **Breaking** (AE-11), the default: on an older guard a database setting switches the guard off, so the engine serves it degraded (`GUARD_OUTDATED`) until `basalt upgrade` or an `UPGRADE` setup code applies this version. Idempotent. Setup also warns about the default itself: [Replication role default](cli.md#cli).

| Object | Purpose |
|---|---|
| `attach` | Replaced, same signature, `SECURITY INVOKER` with `SET search_path = pg_catalog, pg_temp`, owner and grants as version 24's. The same, plus `ALTER TABLE ... ENABLE ALWAYS TRIGGER basalt_guard, ENABLE ALWAYS TRIGGER basalt_guard_truncate` after creating them. It runs as the admin after every migration (`attach_all`), so an upgrade sets both triggers `ENABLE ALWAYS` on every table already guarded. `ALTER TABLE` needs the admin to own the table, as the policy and grants `attach` already sets do |
| `at_commit` on `basalt_meta.changes` | Set `ENABLE ALWAYS` |

### Version 27: a PII column needs USAGE on its schema

Owner decision EV-14. Up to version 26 a column an agent role could `SELECT`, in a schema it had no `USAGE` on, was a readable column and listed by `pii_unclassified()`, though the role, and `basalt classify` scanning as it, got `permission denied for schema` reading it. **Breaking** (AE-11), the default. Idempotent.

| Object | Purpose |
|---|---|
| `pii_readable_columns` | Replaced, same signature, `SECURITY INVOKER`, `STABLE`, owner and grants as version 24's, `SET search_path = pg_catalog, pg_temp`. A column counts only when the member of `<prefix>_agents` that may `SELECT` it also has `USAGE` on its schema ([Readable columns](pii-classification.md#readable-columns-and-the-fingerprint)) |
| `pii_unclassified` | Replaced, same signature, `SECURITY INVOKER`, `STABLE`, owner and grants as version 15's, `SET search_path = pg_catalog, pg_temp`. Lists a column only when `session_user` has `USAGE` on its schema as well as `SELECT` on it |
| `pii_fingerprint` | Not replaced: it is built from `pii_readable_columns`, so a column without schema `USAGE` leaves it too. The fingerprint stored in `pii_catalog` is never compared with the live one, so nothing is rewritten |

### Version 28: one clock for the person's acts, search_path on every routine

Up to version 27 `approved_at` (from version 25) read the wall clock, but `applied_at`, `signed_at` (with the `apply_by` window that starts at it) and `rejected_at` recorded `now()`, the transaction's start, which can be earlier than the deadline check that let the act through. Every time recorded for an act of the person now reads `clock_timestamp()`. Deadlines a function sets for later (`expires_at` of a held write or a prepared revert) still start at `now()`: a transaction that started earlier only shortens them. **Breaking** (AE-11), the default. Idempotent.

| Object | Purpose |
|---|---|
| `apply_revert`, `_revert_sign`, `_revert_finish`, `reject_revert` | Replaced, same signatures, `SECURITY DEFINER`, owner and grants as their latest version, `SET search_path = pg_catalog, pg_temp`. `apply_revert` and `_revert_finish` (the last batch) set `applied_at = clock_timestamp()`; `_revert_sign` sets `signed_at` and `apply_by = signed_at + 24 hours` from one reading; `reject_revert` reads `rejected_at` after locking the revert and returns that value as `rejectedAt` |
| every function and procedure in `basalt_meta` | `search_path` set to `pg_catalog, pg_temp` (`ALTER ROUTINE`, over `prokind` `f` and `p`; version 24's loop took `f` only) |
