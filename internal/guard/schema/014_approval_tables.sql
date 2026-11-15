-- The approval tables: passkeys and approvals, and the changes status
-- constraint with held writes.

-- The person's passkeys (WebAuthn ES256). Public data: the agent views
-- show it so a relay can check a code before submitting it.
CREATE TABLE basalt_meta.passkeys (
    credential_id bytea       PRIMARY KEY CHECK (octet_length(credential_id) BETWEEN 1 AND 1023),
    public_key_x  bytea       NOT NULL CHECK (octet_length(public_key_x) = 32),
    public_key_y  bytea       NOT NULL CHECK (octet_length(public_key_y) = 32),
    rp_id         text        NOT NULL,
    origin        text        NOT NULL,
    sign_count    bigint      NOT NULL DEFAULT 0,
    label         text        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- Held writes (decision #4, M2-1). binding_text is what the passkey signs
-- (sha256 of it); lines, params and binding_text are values, pruned after
-- 30 days.
CREATE TABLE basalt_meta.approvals (
    approval_id      uuid        PRIMARY KEY,
    kind             text        NOT NULL CHECK (kind IN ('APPROVE')),
    agent            name        NOT NULL,
    run_id           uuid        NOT NULL,
    task_id          uuid,
    intent           text        NOT NULL,
    statement        text,
    params           jsonb,
    assigned_columns text[]      NOT NULL,
    lines            text[],
    rows             int         NOT NULL,
    rows_hash        bytea       NOT NULL,
    binding_text     text,
    binding          bytea       NOT NULL,
    held_change      uuid,
    created_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    approved_at      timestamptz,
    credential_id    bytea,
    used_by_change   uuid
);
CREATE INDEX approvals_agent ON basalt_meta.approvals (agent, approval_id);
CREATE INDEX approvals_created ON basalt_meta.approvals (created_at);

ALTER TABLE basalt_meta.changes DROP CONSTRAINT changes_status;
ALTER TABLE basalt_meta.changes ADD CONSTRAINT changes_status
    CHECK (status IN ('APPLIED', 'PREVIEW', 'REFUSED', 'APPROVAL_PENDING', 'APPROVAL_EXPIRED'));
