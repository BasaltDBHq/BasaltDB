-- Version 33 (M4.1, owner decisions VC-21 and CO-18): engine keys and the
-- pinned address (CONTRACT.md, basalt_meta "Version 33" and "Direct
-- transport"). The person's computer records the engine's signing key with
-- the address its tunnel publishes, and the person can revoke an engine.
-- Written only by the admin; an agent role reads the rows through
-- agent_engines, so the bot can neither record a key nor move an address.
--
-- The engine id is computed here from the key, never taken as given, and a
-- revoked key is never recorded again. Rows are never deleted.
-- Non-breaking: an engine on an older guard reports engineRecord UNKNOWN and
-- serves everything else as before. Idempotent.

CREATE TABLE IF NOT EXISTS basalt_meta.engines (
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
REVOKE ALL ON basalt_meta.engines FROM PUBLIC;
