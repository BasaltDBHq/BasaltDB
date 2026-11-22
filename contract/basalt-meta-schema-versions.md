> Part of **`basalt_meta`**. The section starts in [basalt-meta.md](basalt-meta.md).

Changes to `basalt_meta` after the first release. Schema version 1, the files `001` to `011`, is described in [basalt-meta.md](basalt-meta.md), [basalt-meta-revert.md](basalt-meta-revert.md) and [basalt-meta-installs.md](basalt-meta-installs.md). Each later version has one section here, in order, saying what it adds or replaces, whether it is breaking (AE-11) and what an engine does on a guard without it. A section says so when its migration is idempotent. The objects of schema version 2 are described with the rest of the reinstall record, in [Reinstalls on the record](basalt-meta-installs.md#reinstalls-on-the-record). A new change takes the next free number and the next file in `internal/guard/schema/`.

### Schema version 2: install ids

Breaking (the engine and `basalt log` call `install_id()`). Schema version 1 identified a guard install by the oid of the `basalt_meta` schema, which repeats: two clusters made the same way (a Postgres container removed and started again from the same image, then `basalt init`), or a database created from a template that holds the schema, give `basalt_meta` the same oid. A witness's pin of the old ledger was then taken as a pin of the new install and checked against an unrelated ledger: "ledger chain broken" on every check of an untouched ledger. Schema version 2 gives each install a random id; the objects are described in [Reinstalls on the record](basalt-meta-installs.md#reinstalls-on-the-record).

| Object | Change |
|---|---|
| `installs` | Replaced: one row (`id boolean` primary key, always true) with `install uuid`. The upgrade keeps the time, user and Vault user of the row for the current schema oid and gives it a random id; with no such row (`basalt_meta` restored outside the install) it writes a new one, as `basalt init` does |
| `install_id()` | New, granted to `<prefix>_agents` |
| `record_pin_set_aside(bigint, bytea, oid)` | Dropped. Replaced by `record_pin_set_aside(bigint, bytea, uuid)`, which also refuses with detail `NO_INSTALL` |
| `agent_reinstalls` | Recreated with `pinned_install` and `install` as `uuid` (the grant is kept). Ledger rows are never rewritten: a report recorded at schema version 1 keeps its oids in `detail`, and the view shows each such oid as the uuid `00000000-0000-0000-0000-` followed by the oid in 12 hex digits, which no random id is, so the earlier reports of one install still group together |

`basalt init` and `basalt upgrade` write the install row with the statement of the schema version the guard is at after the migrations, so an install that stops at schema version 1 still writes schema version 1's row. After the upgrade, a pin saved at schema version 1 carries no install id and is settled as [Reinstalls on the record](basalt-meta-installs.md#reinstalls-on-the-record) describes: on an unchanged ledger it moves to the new id with the warning, once.

### Schema version 3: plugin events

Non-breaking (AE-11): on a guard without it the agent is served as before, with `GUARD_UPGRADE_AVAILABLE`, but the engine cannot record a plugin event there, so it serves no plugin to that agent ([In the ledger](plugins-ledger.md#in-the-ledger)). Reading the events needs no new object: `agent_ledger` already shows the agent its own rows. Idempotent.

| Object | Change |
|---|---|
| `record_plugin_event(p_kind text, p_detail jsonb) returns bigint` | New. `SECURITY DEFINER`, `SET search_path = pg_catalog, pg_temp`, owned by `<prefix>_guard`, `EXECUTE` for `<prefix>_agents` only, none for `PUBLIC`. Callers must be agent roles (`BS007` `NOT_ALLOWED` otherwise, a superuser included). Appends one ledger row to the chain with `agent` `session_user` (there is no agent argument), the kind, and `p_detail` as the row's detail, and returns its `seq`. Refuses with `BS008` `LEDGER_INPUT_INVALID`, nothing written: a kind other than `PLUGIN_ENABLED`, `PLUGIN_DISABLED`, `PLUGIN_CHANGED` and `PLUGIN_TRUST_ADDED`; a detail that is not a JSON object or is over 4096 bytes as text; a `PLUGIN_TRUST_ADDED` detail other than `signerKeyId` alone, a key id; any other detail that breaks [`events.schema.json`](../api/plugin/events.schema.json): a key outside the list of [In the ledger](plugins-ledger.md#in-the-ledger), a required key missing, or a value of the wrong type, pattern or enum (nested objects included). It is stricter than the schema in one place: `version` must also be a semantic version, the manifest's own pattern, so it holds no free text. A manifest whose record could break these bounds (a `version` over 64 bytes, or an `egress` list so long that the detail could exceed 4 KiB) is refused when it is verified (`BAD_MANIFEST`), so every plugin a person consents to can be recorded. The error names the rule, never the value given |
| `_check_plugin_detail(p_detail jsonb)` | New, internal (no grants): the detail rules above |

### Schema version 4: plugin trust removed

Non-breaking (AE-11): on a guard without it the agent and its plugins are served as before, with `GUARD_UPGRADE_AVAILABLE`, but the engine cannot write `PLUGIN_TRUST_REMOVED` there, so a key the trust store no longer holds stays recorded as trusted (logged, tried again at each start). Idempotent.

| Object | Change |
|---|---|
| `record_plugin_event(p_kind text, p_detail jsonb) returns bigint` | Replaced (owner and grants kept). Also takes `PLUGIN_TRUST_REMOVED`, whose detail is `signerKeyId` alone, a key id, as for `PLUGIN_TRUST_ADDED`; every other rule is schema version 3's |

### Schema version 5: plugin approvals

[Plugin approval](plugins-approval.md#plugin-approval), file `015_plugin_approvals.sql`, following the revert pattern. The next free version after 4; if another migration takes 5 first, this one takes the next free number and every "schema version 5" in this file moves with it. **Non-breaking** (AE-11): on a guard without it the agent and its other plugins are served as before, with `GUARD_UPGRADE_AVAILABLE`; an entry that requires approval is withheld from that agent (`PLUGIN_UNAVAILABLE`, [Plugin approvals at engine start](plugins-approval.md#plugin-approvals-at-engine-start)), and `request_plugin` refuses to open an approval there (`PLUGIN_REFUSED` `GUARD_OUTDATED`): the guard is updated first, as `status` says. No other admin step is added. New installs get it with the rest. Idempotent.

| Object | Change |
|---|---|
| `plugin_approvals` | New table, no grants to agents: `approval_id uuid` (primary key, UUIDv7), `name`, `instance`, `opened_by` (the opening role), `agents text[]` (sorted), `detail jsonb` (the validated detail), `settings_text text`, `binding_text text`, `binding bytea` (its `sha256`, the challenge), `opened_at`, `expires_at`, `status` (`PENDING`, `APPROVED`, `CANCELLED`), `approved_at`, `credential_id bytea`. No row values: nothing to prune |
| `plugin_approval_ends` | New table, no grants to agents: `(approval_id, agent)` primary key, `ended_at`: a signed approval that a `PLUGIN_DISABLED` ended for that agent role |
| `open_plugin_approval(p_detail jsonb, p_settings jsonb) returns table (approval_id uuid, binding_text text, settings_text text, expires_at timestamptz)` | Agent roles. Validates the detail and the settings ([What a plugin approval binds](plugins-approval.md#what-a-plugin-approval-binds); `BS008` `LEDGER_INPUT_INVALID` otherwise, the error naming the rule, never the value), checks every role in `agents` is a member of `<prefix>_agents` (`BS007` detail `UNKNOWN_AGENT`), marks earlier `PENDING` approvals of the same `(name, instance)` `CANCELLED`, refuses when 8 unexpired `PENDING` approvals remain (`BS007` detail `TOO_MANY_PENDING`), builds `change`, the settings text and the binding text, stores the row, and appends `PLUGIN_APPROVAL_PENDING` to the caller's ledger. `expires_at` is 24 hours after `clock_timestamp()` |
| `submit_plugin_approval(p_approval_id uuid, p_credential_id bytea, p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea) returns timestamptz` | Any agent role, as a relay. Calls `_verify_assertion` with the approval's `binding` (the checks of [Checks in Postgres](approvals.md#checks-in-postgres)), then marks the approval `APPROVED` with the credential id and appends `PLUGIN_APPROVED` to the ledger of every role in `agents`. Refuses, writing nothing: an unknown id or one that is not `PENDING` (`BS005` `APPROVAL_INVALID`, detail `NOT_FOUND`, `CANCELLED` or `ALREADY_APPROVED`), a pending one past `expires_at` (`BS005` `APPROVAL_EXPIRED`), and every `_verify_assertion` failure. It decides nothing about who may sign beyond `_verify_assertion`: any passkey of the database may sign, as for held writes, so signing rules added later go in that one shared place. Returns `approved_at` |
| `agent_plugin_approvals` | View, `SELECT` for `<prefix>_agents`: the plugin approvals that name the calling role or that it opened. `approval_id`, `name`, `instance`, `status` (`PENDING`, `APPROVED`, `CANCELLED`, and `EXPIRED` for a pending one past `expires_at`), `opened_at`, `expires_at`, `approved_at`, `names_caller boolean`, `ended_at` (for the caller, from `plugin_approval_ends`), `detail` (the `PLUGIN_APPROVAL_PENDING` detail, which names no agent), and `binding_text` and `settings_text`, which are `NULL` except for the role that opened it (they list the other agents). The engine's check and `request_plugin`'s wait read it |
| `record_plugin_event(p_kind text, p_detail jsonb) returns bigint` | Replaced (owner and grants kept). An entry detail may carry `signer` (`KNOWN` or `UNKNOWN`); with `UNKNOWN` it has no `signerKeyId`, otherwise `signerKeyId` is required as before ([`events.schema.json`](../api/plugin/events.schema.json)). It still refuses every kind but the five of schema version 4, so `PLUGIN_APPROVAL_PENDING` and `PLUGIN_APPROVED` with `BS008`. A `PLUGIN_DISABLED` also records, in `plugin_approval_ends`, the caller as ended for every `APPROVED` approval of that `(name, instance)` that names it |
| `_check_plugin_detail(p_detail jsonb)` | Replaced: the `signer` rule above |

Every function `SECURITY DEFINER`, owned by `<prefix>_guard`, `SET search_path = pg_catalog, pg_temp`, `EXECUTE` for `<prefix>_agents` only (none for `PUBLIC`); callers must be agent roles (`BS007` `NOT_ALLOWED` otherwise). Clock: `clock_timestamp()`. Postgres builds every text; no client re-serialises one.

### Schema version 6: trust pins

[Pinning on first use](trust.md#pinning-on-first-use), file `016_trust_pins.sql`. **Non-breaking** (AE-11): on a guard without it every tool is served as before, with `GUARD_UPGRADE_AVAILABLE`; `basalt init` cannot record a pin there (it says so and goes on), and `status` has no record to compare a pin with. Idempotent.

| Object | Change |
|---|---|
| `record_trust_pin(p_host text, p_port int, p_sha256 text) returns bigint` | New. Admin only: `SECURITY DEFINER`, owned by `<prefix>_guard`, `SET search_path = pg_catalog, pg_temp`, `EXECUTE` revoked from `PUBLIC` and granted to no one, and it refuses an agent role itself (`BS007` `NOT_ALLOWED`) even when given `EXECUTE`. `p_host` a lowercase host name or an address, up to 253 characters; `p_port` 1 to 65535; `p_sha256` the SHA-256 of the pinned certificate's DER, 64 lowercase hex digits (`BS008` `LEDGER_INPUT_INVALID` otherwise). Appends `TRUST_PIN_RECORDED`, `agent` the admin role, detail `{ "host", "port", "sha256", "by" }`; returns its seq |
| `agent_trust_pins` | New view, `SELECT` for `<prefix>_agents`: the latest `TRUST_PIN_RECORDED` per host and port (`host`, `port`, `sha256`, `recorded_at`). Not secret: a fingerprint of a certificate the server presents to anyone. `status` reads it on the agent's connection (`TRUST_PIN_MISMATCH`) |

### Schema version 7: shorter setup-code life

[Valid for 10 minutes, single use (CO-13)](setup.md#the-setup-code), file `017_setup_code_life.sql`. **Non-breaking** (AE-11): on a guard without it every tool is served as before, with `GUARD_UPGRADE_AVAILABLE`. A setup that already confirmed a live code may fail `EXPIRED` at `record_setup` on a guard below this version if the 10 minutes have passed, since that guard has no grace. A code made by an older `basalt` (24-hour `expiresAt`) is refused `EXPIRY_TOO_FAR` by a guard at this version: the person asks for a new link; `basalt upgrade` applies the new `record_setup`. New installs get it with the rest. Idempotent.

| Object | Change |
|---|---|
| `record_setup(setup_id uuid, kind text, agent name, guard_version int, expires_at timestamptz) returns bigint` | Replaced (owner and grants kept). `EXPIRY_TOO_FAR` is now an `expires_at` more than 10 minutes and 5 minutes after the clock reading, or more than 10 minutes after the `setup_id`'s time (it was 24 hours). `EXPIRED` now has a grace of 30 minutes, the length of the address hold: it is refused only when the clock reading is more than 30 minutes past `expires_at` (it was refused from `expires_at` on). Opening and confirming a code need a live `expiresAt`, and a run that already passed those checks may finish within the grace. `USED`, `SUPERSEDED`, `SETUP_ID_IN_FUTURE` and every other rule are unchanged |

### Schema version 8: engine address removed

The direct transport is [removed](cli.md#removed), and with it the engine address recorded with an engine's key ([Engine records](basalt-meta-installs.md#engine-records)). File `018_engine_address_removed.sql`. **Non-breaking** (AE-11): the engine reads only `engine_id`, `public_key`, `recorded_at` and `revoked_at` from `agent_engines`, which a guard without it has too, so every tool is served as before, with `GUARD_UPGRADE_AVAILABLE`. An older engine on a version 8 guard is served as before, but its `engineRecord` reads `UNKNOWN` and its `basalt engine list` fails until it is updated: both read the removed `url` column. Only an older setup that records an engine fails there: the two-argument `record_engine` it calls no longer exists, so its transaction rolls back and nothing changes, and the person updates `basalt`. A setup that leaves the guard below version 8 records its engine with `record_engine(<key>, NULL)`. Idempotent.

| Object | Change |
|---|---|
| `engines` | Column `url` dropped. Rows and their revocation are kept |
| `agent_engines` | Recreated without `url` (`security_barrier`, `SELECT` for `<prefix>_agents`) |
| `record_engine(public_key bytea) returns text` | Replaces `record_engine(public_key bytea, url text)`, which is dropped. Owned by `<prefix>_guard`, `EXECUTE` revoked from `PUBLIC`. Inserts a new key with an `ENGINE_RECORDED` row (detail `engineId`, `by`), changes nothing for a key already recorded, and refuses a revoked key (`ENGINE_REVOKED`) and a malformed one (`ENGINE_KEY`) |
| `revoke_engine(engine_id text) returns int` | Replaced (owner and grants kept). Its `ENGINE_REVOKED` detail no longer names `url` |
| `_engine_url_ok(text)` | Dropped |
