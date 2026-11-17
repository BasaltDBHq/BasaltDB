-- The guard's tables and types, with their indexes and the rows a new
-- install starts with, and the functions their column defaults and
-- generated columns call. Agents never write these tables directly: rows
-- go through the validating SECURITY DEFINER functions of the later files.

-- No function in basalt_meta is executable by PUBLIC: every function the
-- guard role creates from here on starts without that privilege, and
-- 010_grants.sql grants the agents group exactly what it may call.
ALTER DEFAULT PRIVILEGES FOR ROLE {{guard}} REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- UUIDv7 (RFC 9562): 48-bit Unix milliseconds over a random v4, version
-- bits set to 0111. Core functions only; Postgres 18's uuidv7() is not
-- available on 15 to 17.
CREATE FUNCTION basalt_meta._uuidv7() RETURNS uuid
LANGUAGE sql VOLATILE SET search_path = pg_catalog, pg_temp AS $$
    SELECT encode(set_bit(set_bit(
        overlay(uuid_send(gen_random_uuid())
                PLACING substring(int8send((extract(epoch FROM clock_timestamp()) * 1000)::bigint) FROM 3)
                FROM 1 FOR 6),
        52, 1), 53, 1), 'hex')::uuid
$$;

-- 16 random bytes for a revert's rescope nonce, from pg_strong_random
-- (gen_random_uuid): two v4 uuids carry 244 random bits, hashed down.
CREATE OR REPLACE FUNCTION basalt_meta._revert_nonce() RETURNS bytea
LANGUAGE sql VOLATILE SET search_path = pg_catalog, pg_temp AS $$
    SELECT substring(sha256(uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid())) FROM 1 FOR 16)
$$;

-- The agents of a descriptor as roles, NULL when it selects every agent.
-- IMMUTABLE: reverts.agents is generated from it.
CREATE OR REPLACE FUNCTION basalt_meta._revert_select_agents(p_sel jsonb) RETURNS name[]
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT CASE WHEN jsonb_typeof(p_sel -> 'agents') = 'array'
                THEN ARRAY(SELECT a::name FROM jsonb_array_elements_text(p_sel -> 'agents') a) END
$$;

-- True when a descriptor covers changes not made by p_role: its agents is
-- null (every agent) or names another role. IMMUTABLE: reverts.widened is
-- generated from it.
CREATE OR REPLACE FUNCTION basalt_meta._widened(p_sel jsonb, p_role name) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT jsonb_typeof(p_sel -> 'agents') IS DISTINCT FROM 'array'
        OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(p_sel -> 'agents') a WHERE a <> p_role::text)
$$;

-- Every table carrying the guard and why (coverage reads this).
CREATE TABLE basalt_meta.guarded_tables (
    table_oid regclass PRIMARY KEY,
    pk_cols   text[]   NOT NULL,
    reason    text     NOT NULL CHECK (reason IN ('AGENT_WRITABLE', 'CASCADE_TARGET'))
);

-- One row per run (run_start). The task id is shared across agents.
CREATE TABLE basalt_meta.runs (
    run_id     uuid        PRIMARY KEY,
    task_id    uuid,
    agent      name        NOT NULL,
    intent     text        NOT NULL,
    started_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX runs_started_at ON basalt_meta.runs (started_at);

-- list_runs: an agent's own runs by id.
CREATE INDEX runs_agent ON basalt_meta.runs (agent, run_id);

-- The change record: one row per agent action, which is one top-level
-- statement in one transaction, keyed by (tx, stmt_ts) while it is written.
-- A revert the person applied is one change too (op REVERT, actor_kind
-- PERSON, revert_id and the passkey's credential_id); reverted_by lists
-- the reverts that restored a change's rows.
CREATE TABLE basalt_meta.changes (
    change_id     uuid        PRIMARY KEY DEFAULT basalt_meta._uuidv7(),
    tx            xid8        NOT NULL,
    stmt_ts       timestamptz NOT NULL,
    at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    agent         name        NOT NULL,
    run_id        uuid,
    task_id       uuid,
    intent        text,
    op            text,
    table_name    text,
    statement     text,
    params        jsonb,
    rows          int         NOT NULL DEFAULT 0,
    cascaded_rows int         NOT NULL DEFAULT 0,
    has_delete    boolean     NOT NULL DEFAULT false,
    mode          text        NOT NULL DEFAULT 'APPLY' CONSTRAINT changes_mode CHECK (mode IN ('APPLY', 'PREVIEW')),
    approval_id   uuid,
    duration_ms   int,
    status        text        NOT NULL CONSTRAINT changes_status
                              CHECK (status IN ('APPLIED', 'PREVIEW', 'REFUSED', 'APPROVAL_PENDING', 'APPROVAL_EXPIRED', 'REVERTED')),
    code          text,
    reason        text,
    actor_kind    text        NOT NULL DEFAULT 'AGENT' CONSTRAINT changes_actor_kind CHECK (actor_kind IN ('AGENT', 'PERSON')),
    revert_id     uuid,
    credential_id bytea,
    reverted_by   uuid[],
    UNIQUE (tx, stmt_ts)
);

CREATE INDEX changes_agent ON basalt_meta.changes (agent, change_id);

CREATE INDEX changes_run ON basalt_meta.changes (run_id, change_id);

CREATE INDEX changes_at ON basalt_meta.changes (at);

CREATE INDEX changes_task ON basalt_meta.changes (task_id, change_id);

-- The task proposal's lookup by (task_id, agent), so its cost does not grow
-- with other agents' changes in the task (that growth would be a timing signal).
CREATE INDEX changes_task_agent ON basalt_meta.changes (task_id, agent, change_id);

-- Append-only, hash-chained ledger. Rows are written only by _append.
CREATE TABLE basalt_meta.ledger (
    seq           bigint      PRIMARY KEY,
    at            timestamptz NOT NULL,
    agent         name        NOT NULL,
    change_id     uuid,
    kind          text        NOT NULL,
    table_name    text,
    table_oid     oid,
    op            text,
    row_key       jsonb,
    old_row       jsonb,
    new_row       jsonb,
    values_hash   bytea       NOT NULL,
    values_pruned boolean     NOT NULL DEFAULT false,
    depth         int,
    detail        jsonb,
    prev_hash     bytea       NOT NULL,
    hash          bytea       NOT NULL
);

CREATE INDEX ledger_change ON basalt_meta.ledger (change_id);

CREATE INDEX ledger_agent_kind ON basalt_meta.ledger (agent, kind, seq);

CREATE INDEX ledger_at ON basalt_meta.ledger (at);

-- The latest ledger row of a row, for ALREADY_REVERTED.
CREATE INDEX ledger_table_key ON basalt_meta.ledger (table_oid, row_key, seq) WHERE kind = 'ROW_CHANGE';

-- Last appended (seq, hash). Its row lock serializes appends until commit.
CREATE TABLE basalt_meta.chain_head (
    id   boolean PRIMARY KEY DEFAULT true CHECK (id),
    seq  bigint  NOT NULL,
    hash bytea   NOT NULL
);

INSERT INTO basalt_meta.chain_head VALUES (true, 0, '\x0000000000000000000000000000000000000000000000000000000000000000');

-- Where verification starts: (0, zero hash) until retention deletes the
-- oldest rows, then the last deleted row's (seq, hash).
CREATE TABLE basalt_meta.chain_anchor (
    id   boolean PRIMARY KEY DEFAULT true CHECK (id),
    seq  bigint  NOT NULL,
    hash bytea   NOT NULL
);

INSERT INTO basalt_meta.chain_anchor VALUES (true, 0, '\x0000000000000000000000000000000000000000000000000000000000000000');

-- A run's latest known version of each row it read or wrote (owner
-- decisions #7 and #15). Removed with the run by retention (1 year).
CREATE TABLE basalt_meta.reads (
    run_id      uuid        NOT NULL REFERENCES basalt_meta.runs ON DELETE CASCADE,
    table_oid   oid         NOT NULL,
    row_key     jsonb       NOT NULL,
    row_version xid         NOT NULL,
    change_id   uuid,
    at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (run_id, table_oid, row_key)
);

-- The person's passkeys (WebAuthn ES256). Public data: the agent views
-- show it so a relay can check a code before submitting it. WebAuthn never
-- tells the server a passkey was deleted, so the person revokes it here
-- (revoked_at, revoked_by); a revoked passkey signs nothing. Rows are kept.
-- user_handle is the WebAuthn user id the passkey was created with.
CREATE TABLE basalt_meta.passkeys (
    credential_id bytea       PRIMARY KEY CHECK (octet_length(credential_id) BETWEEN 1 AND 1023),
    public_key_x  bytea       NOT NULL CHECK (octet_length(public_key_x) = 32),
    public_key_y  bytea       NOT NULL CHECK (octet_length(public_key_y) = 32),
    rp_id         text        NOT NULL,
    origin        text        NOT NULL,
    sign_count    bigint      NOT NULL DEFAULT 0,
    label         text        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    user_handle   bytea       CHECK (octet_length(user_handle) BETWEEN 1 AND 64),
    last_used_at  timestamptz,
    revoked_at    timestamptz,
    revoked_by    name
);

-- Held writes (decision #4, M2-1). binding_text is what the passkey signs
-- (sha256 of it); lines, params and binding_text are values, pruned after
-- 30 days. reveal_nonce (16 random bytes from the column default, so
-- hold_action sets it unchanged) and the reveal ticket's hash and deadline
-- serve the person's reveal of redacted lines; agent_approvals lists its
-- columns, so it shows none of them.
CREATE TABLE basalt_meta.approvals (
    approval_id        uuid        PRIMARY KEY,
    kind               text        NOT NULL CHECK (kind IN ('APPROVE')),
    agent              name        NOT NULL,
    run_id             uuid        NOT NULL,
    task_id            uuid,
    intent             text        NOT NULL,
    statement          text,
    params             jsonb,
    assigned_columns   text[]      NOT NULL,
    lines              text[],
    rows               int         NOT NULL,
    rows_hash          bytea       NOT NULL,
    binding_text       text,
    binding            bytea       NOT NULL,
    held_change        uuid,
    created_at         timestamptz NOT NULL DEFAULT now(),
    expires_at         timestamptz NOT NULL,
    approved_at        timestamptz,
    credential_id      bytea,
    used_by_change     uuid,
    reveal_nonce       bytea       NOT NULL DEFAULT basalt_meta._revert_nonce(),
    reveal_ticket_hash bytea,
    reveal_until       timestamptz
);

CREATE INDEX approvals_agent ON basalt_meta.approvals (agent, approval_id);

CREATE INDEX approvals_created ON basalt_meta.approvals (created_at);

-- One row as the scope changed it: the first and last in-scope ledger rows,
-- the key it had before (orig_key) and has now (cur_key), the values to
-- restore (old_row of the first) and the values and version the agent left
-- (new_row and new_xmin of the last). broken: someone wrote the row between
-- two in-scope changes.
CREATE TYPE basalt_meta.revert_chain AS (
    table_oid  oid,
    table_name text,
    first_seq  bigint,
    last_seq   bigint,
    first_op   text,
    last_op    text,
    orig_key   jsonb,
    cur_key    jsonb,
    old_row    jsonb,
    new_row    jsonb,
    new_xmin   text,
    cascaded   boolean,
    pruned     boolean,
    broken     boolean,
    change_ids uuid[]
);

-- One line of a revert: the inverse write (op on key, writing set), the
-- row as it is now, and the conflict that skips it (NULL to restore).
-- step is the order a trial write succeeded in (deletes, updates,
-- re-inserts, FK retries): a batched plan's lines are numbered in it, so
-- applying them in number order lands parents before children across
-- batches.
CREATE TYPE basalt_meta.revert_item AS (
    table_oid  oid,
    table_name text,
    op         text,
    key        jsonb,
    now        jsonb,
    set        jsonb,
    conflict   text,
    sql_state  text,
    cascaded   boolean,
    change_ids uuid[],
    first_seq  bigint,
    last_seq   bigint,
    step       int
);

-- The transaction a revert (or its trial) runs in, and the one row it may
-- write next. Written and deleted only inside the revert functions; agents
-- have no privilege on it. A trial's writes are rolled back, so the guard
-- records nothing for them (trial).
CREATE UNLOGGED TABLE basalt_meta.revert_running (
    tx           xid8    PRIMARY KEY,
    agent        name    NOT NULL,
    change_id    uuid    NOT NULL,
    revert_of    uuid[],
    target_table oid,
    target_key   jsonb,
    trial        boolean NOT NULL DEFAULT false
);

-- Prepared reverts (decisions M3-6, M3-12). binding_text is what the
-- passkey signs (sha256 of it); lines and binding_text are values, pruned
-- after 30 days. Up to 1000 lines a revert is prepared, signed and applied
-- in one call; a larger one is batched: every line is stored in
-- revert_lines, the person signs one binding over all of them, and the role
-- that prepared it applies the plan in batches.
--
-- selection is the revert's scope descriptor and proposed the one the
-- agent asked for; ceiling and scope_token_hash hold a widen proof the
-- person signed; rescope_nonce is what the next widen proof signs. scope,
-- scope_id and agents are generated from selection, so they cannot
-- disagree with it; widened tells whether it covers changes not made by
-- the requesting role. reveal_nonce serves the person's reveal of
-- redacted lines, as in approvals.
CREATE TABLE basalt_meta.reverts (
    revert_id        uuid        PRIMARY KEY,
    requested_by     name        NOT NULL,
    intent           text        NOT NULL,
    lines            text[],
    rows             int         NOT NULL,
    skipped          int         NOT NULL,
    rows_hash        bytea       NOT NULL,
    binding_text     text,
    binding          bytea       NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    applied_at       timestamptz,
    credential_id    bytea,
    change_id        uuid,
    batched          boolean     NOT NULL DEFAULT false,
    sample_hash      bytea,
    covered          uuid[],
    signed_at        timestamptz,
    apply_by         timestamptz,
    batches          int         NOT NULL DEFAULT 0,
    selection        jsonb       NOT NULL,
    proposed         jsonb       NOT NULL,
    ceiling          jsonb,
    scope_token_hash bytea,
    rescope_nonce    bytea       NOT NULL,
    rescoped         int         NOT NULL DEFAULT 0,
    rejected_at      timestamptz,
    reject_note      text,
    scope            text        GENERATED ALWAYS AS (selection ->> 'scope') STORED
                                 CONSTRAINT reverts_scope CHECK (scope IN ('CHANGE', 'RUN', 'TASK')),
    scope_id         uuid        GENERATED ALWAYS AS ((selection ->> 'scopeId')::uuid) STORED,
    agents           name[]      GENERATED ALWAYS AS (basalt_meta._revert_select_agents(selection)) STORED,
    widened          boolean     NOT NULL GENERATED ALWAYS AS (basalt_meta._widened(selection, requested_by)) STORED,
    reveal_nonce     bytea       NOT NULL DEFAULT basalt_meta._revert_nonce(),
    CONSTRAINT reverts_ceiling_token CHECK ((ceiling IS NULL) = (scope_token_hash IS NULL)),
    CONSTRAINT reverts_reject_note CHECK (char_length(reject_note) <= 500)
);

CREATE INDEX reverts_requested ON basalt_meta.reverts (requested_by, revert_id);

CREATE INDEX reverts_created ON basalt_meta.reverts (created_at);

-- A batched plan's lines: the signed text (redacted for the preparing
-- role, as every line), the row's ledger chain to re-check it at apply
-- time, and what happened to it. line and chain are values, pruned after
-- 30 days.
CREATE TABLE basalt_meta.revert_lines (
    revert_id uuid NOT NULL REFERENCES basalt_meta.reverts ON DELETE CASCADE,
    line_no   int  NOT NULL,
    line      text,
    chain     basalt_meta.revert_chain,
    outcome   text NOT NULL DEFAULT 'PENDING'
              CONSTRAINT revert_lines_outcome CHECK (outcome IN ('PENDING', 'RESTORED', 'SKIPPED')),
    conflict  text,
    sql_state text,
    batch     int,
    PRIMARY KEY (revert_id, line_no)
);

CREATE INDEX revert_lines_pending ON basalt_meta.revert_lines (revert_id, line_no) WHERE outcome = 'PENDING';

-- PII classification: one class per column an agent can read, written only
-- by basalt classify under SET LOCAL ROLE {{guard}}.
CREATE TABLE basalt_meta.pii_columns (
    table_schema          text    NOT NULL,
    table_name            text    NOT NULL,
    column_name           text    NOT NULL,
    data_type             text    NOT NULL,
    class                 text    NOT NULL
        CHECK (class IN ('PUBLIC', 'IDENTIFIER', 'FREE_TEXT', 'SECRET', 'UNCLASSIFIED')),
    entity_type           text
        CHECK (entity_type IN ('EMAIL', 'PHONE', 'PERSON_NAME', 'ADDRESS', 'OTHER')),
    suggested_class       text
        CHECK (suggested_class IN ('PUBLIC', 'IDENTIFIER', 'FREE_TEXT', 'SECRET', 'UNCLASSIFIED')),
    suggested_entity_type text
        CHECK (suggested_entity_type IN ('EMAIL', 'PHONE', 'PERSON_NAME', 'ADDRESS', 'OTHER')),
    reason                text,
    needs_review          boolean NOT NULL DEFAULT false,
    phone_region          text    CHECK (phone_region ~ '^[A-Z]{2}$'),
    confirmed_at          timestamptz,
    confirmed_by          text,
    PRIMARY KEY (table_schema, table_name, column_name),
    CONSTRAINT pii_columns_entity_type CHECK ((entity_type IS NOT NULL) = (class = 'IDENTIFIER')),
    CONSTRAINT pii_columns_suggested_entity_type
        CHECK ((suggested_entity_type IS NOT NULL) = coalesce(suggested_class = 'IDENTIFIER', false)),
    CONSTRAINT pii_columns_phone_region CHECK (phone_region IS NULL OR entity_type = 'PHONE'),
    -- Confirmed exactly when a person gave the column a class.
    CONSTRAINT pii_columns_confirmed CHECK (CASE WHEN class = 'UNCLASSIFIED'
        THEN confirmed_at IS NULL AND confirmed_by IS NULL
        ELSE confirmed_at IS NOT NULL AND confirmed_by IS NOT NULL END)
);

-- At most one row: the fingerprint when basalt classify last wrote.
CREATE TABLE basalt_meta.pii_catalog (
    id            boolean     PRIMARY KEY DEFAULT true CHECK (id),
    fingerprint   bytea       NOT NULL CHECK (octet_length(fingerprint) = 32), -- sha256
    classified_at timestamptz NOT NULL,
    classified_by text        NOT NULL
);

-- One row per setup code that ran, written only by the admin's
-- record_setup inside the transaction of basalt init --setup-code.
CREATE TABLE basalt_meta.setups (
    setup_id      uuid        PRIMARY KEY, -- the code's UUIDv7, so a code runs once
    kind          text        NOT NULL CHECK (kind IN ('INSTALL', 'AGENT', 'UPGRADE')),
    agent_role    name,
    guard_version int         NOT NULL CHECK (guard_version > 0),
    expires_at    timestamptz NOT NULL,
    used_at       timestamptz NOT NULL DEFAULT now(),
    used_by       name        NOT NULL DEFAULT session_user,
    CONSTRAINT setups_agent_role CHECK ((agent_role IS NULL) = (kind = 'UPGRADE'))
);

CREATE INDEX setups_by_agent ON basalt_meta.setups (agent_role, setup_id);

-- Engine keys and the pinned address: the person's computer records the
-- engine's signing key (and the address given as --engine-url) here, and
-- revokes it; rows are kept.
CREATE TABLE basalt_meta.engines (
    engine_id   text        PRIMARY KEY CHECK (engine_id ~ '^[A-Za-z0-9_-]{22}$'),
    public_key  bytea       NOT NULL UNIQUE CHECK (pg_catalog.octet_length(public_key) = 91),
    url         text,
    recorded_at timestamptz NOT NULL,
    recorded_by name        NOT NULL,
    updated_at  timestamptz NOT NULL,
    revoked_at  timestamptz,
    revoked_by  name,
    CONSTRAINT engines_revoked CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);

-- This install of the guard: one row, written by the install transaction
-- (here, and again by basalt init after the migrations, which changes
-- nothing for an install that has its row). install is a random id, so no
-- other install can have it: a schema oid repeats across clusters made the
-- same way. A copy of basalt_meta (a restore, a template database) keeps it.
CREATE TABLE basalt_meta.installs (
    id           boolean     PRIMARY KEY DEFAULT true CHECK (id),
    install      uuid        NOT NULL,
    installed_at timestamptz NOT NULL,
    installed_by name        NOT NULL,
    vault_user   text
);
{{record_install_row}}
