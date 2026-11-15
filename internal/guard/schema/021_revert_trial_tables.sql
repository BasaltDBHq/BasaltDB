-- Version 6 (M3, part 2): the revert runs on trial. The guard role writes
-- the plan inside a subtransaction that always rolls back, so CASCADE and
-- CONSTRAINT conflicts are known before the person signs (decision M3-7);
-- prepare_revert stores the lines and the binding the passkey signs. The
-- guard trigger tells a revert write from an agent write by a row in
-- revert_running for the current transaction, which only the revert
-- functions write. Same rules as schema.go: forward-only, schema-qualified,
-- role names only through Names.render.

-- The transaction a revert (or its trial) runs in, and the one row it may
-- write next. Written and deleted only inside the revert functions; agents
-- have no privilege on it.
CREATE UNLOGGED TABLE basalt_meta.revert_running (
    tx           xid8   PRIMARY KEY,
    agent        name   NOT NULL,
    change_id    uuid   NOT NULL,
    revert_of    uuid[],
    target_table oid,
    target_key   jsonb
);

-- Prepared reverts (decisions M3-6, M3-12). binding_text is what the
-- passkey signs (sha256 of it); lines and binding_text are values, pruned
-- after 30 days.
CREATE TABLE basalt_meta.reverts (
    revert_id     uuid        PRIMARY KEY,
    scope         text        NOT NULL CHECK (scope IN ('CHANGE', 'RUN', 'TASK')),
    scope_id      uuid        NOT NULL,
    agents        name[]      NOT NULL,
    requested_by  name        NOT NULL,
    intent        text        NOT NULL,
    lines         text[],
    rows          int         NOT NULL,
    skipped       int         NOT NULL,
    rows_hash     bytea       NOT NULL,
    binding_text  text,
    binding       bytea       NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    applied_at    timestamptz,
    credential_id bytea,
    change_id     uuid
);
CREATE INDEX reverts_requested ON basalt_meta.reverts (requested_by, revert_id);
CREATE INDEX reverts_created ON basalt_meta.reverts (created_at);
REVOKE ALL ON basalt_meta.revert_running, basalt_meta.reverts FROM PUBLIC;
