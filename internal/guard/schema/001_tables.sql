-- The ledger's tables: runs, changes, guarded_tables, ledger, the chain
-- head and anchor, and the UUIDv7 generator.

-- UUIDv7 (RFC 9562): 48-bit Unix milliseconds over a random v4, version
-- bits set to 0111. Core functions only; Postgres 18's uuidv7() is not
-- available on 15 to 17.
CREATE FUNCTION basalt_meta._uuidv7() RETURNS uuid
LANGUAGE sql VOLATILE SET search_path = pg_catalog AS $$
    SELECT encode(set_bit(set_bit(
        overlay(uuid_send(gen_random_uuid())
                PLACING substring(int8send((extract(epoch FROM clock_timestamp()) * 1000)::bigint) FROM 3)
                FROM 1 FOR 6),
        52, 1), 53, 1), 'hex')::uuid
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

-- The change record: one row per agent action, which is one top-level
-- statement in one transaction, keyed by (tx, stmt_ts) while it is written.
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
    status        text        NOT NULL CONSTRAINT changes_status CHECK (status IN ('APPLIED', 'PREVIEW', 'REFUSED')),
    code          text,
    reason        text,
    UNIQUE (tx, stmt_ts)
);
CREATE INDEX changes_agent ON basalt_meta.changes (agent, change_id);
CREATE INDEX changes_run ON basalt_meta.changes (run_id, change_id);
CREATE INDEX changes_at ON basalt_meta.changes (at);

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
