-- Version 16 (M4): setups (CONTRACT.md, basalt_meta "Version 16" and "Setup
-- from your laptop"). One row per setup code that ran, written only by the
-- admin's record_setup inside the transaction of basalt init --setup-code.
-- The database's clock decides expiry and order, not the code's. The step
-- is idempotent: re-running it keeps the rows.

CREATE TABLE IF NOT EXISTS basalt_meta.setups (
    setup_id      uuid        PRIMARY KEY, -- the code's UUIDv7, so a code runs once
    kind          text        NOT NULL CHECK (kind IN ('INSTALL', 'AGENT', 'UPGRADE')),
    agent_role    name,
    guard_version int         NOT NULL CHECK (guard_version > 0),
    expires_at    timestamptz NOT NULL,
    used_at       timestamptz NOT NULL DEFAULT now(),
    used_by       name        NOT NULL DEFAULT session_user,
    CONSTRAINT setups_agent_role CHECK ((agent_role IS NULL) = (kind = 'UPGRADE'))
);
CREATE INDEX IF NOT EXISTS setups_by_agent ON basalt_meta.setups (agent_role, setup_id);
REVOKE ALL ON basalt_meta.setups FROM PUBLIC;
