package guard

// Version 16 (M4): setups (CONTRACT.md, basalt_meta "Version 16" and "Setup
// from your laptop"). One row per setup code that ran, written only by the
// admin's record_setup inside the transaction of basalt init --setup-code.
// The database's clock decides expiry and order, not the code's. The step
// is idempotent: re-running it keeps the rows.

const v16Tables = `
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
CREATE INDEX IF NOT EXISTS setups_agent_role ON basalt_meta.setups (agent_role, setup_id);
REVOKE ALL ON basalt_meta.setups FROM PUBLIC;
`

const v16Functions = `
CREATE OR REPLACE FUNCTION basalt_meta._setup_refused(p_reason text, p_hint text) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'BS010', MESSAGE = 'SETUP_REFUSED', DETAIL = p_reason, HINT = p_hint;
END $$;

-- Admin only (basalt init --setup-code): record a setup code in the
-- install's transaction and append its AGENT_SETUP ledger row. Refuses a
-- code already used, one older than the agent's latest recorded setup
-- (UUIDv7 ids are time-ordered), and one whose times the database's clock
-- rejects. Returns the ledger seq.
CREATE OR REPLACE FUNCTION basalt_meta.record_setup(
    p_setup_id uuid, p_kind text, p_agent name, p_guard_version int, p_expires_at timestamptz
) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    c_skew       constant interval := interval '5 minutes';
    c_lifetime   constant interval := interval '24 hours';
    c_hex_ms_len constant int      := 12; -- the first 48 bits of a UUIDv7, in hex
    c_version    constant int      := 15; -- 1-based position of the version digit in uuid text
    v_hex      text := replace(p_setup_id::text, '-', '');
    v_id_at    timestamptz;
    v_used_at  timestamptz;
    v_actor    name;
BEGIN
    IF p_setup_id IS NULL OR substr(p_setup_id::text, c_version, 1) <> '7' THEN
        PERFORM basalt_meta._invalid('setup id must be a UUIDv7');
    END IF;
    IF p_kind IS NULL OR p_kind NOT IN ('INSTALL', 'AGENT', 'UPGRADE') THEN
        PERFORM basalt_meta._invalid('kind must be INSTALL, AGENT or UPGRADE');
    END IF;
    IF p_guard_version IS NULL OR p_guard_version < 1 THEN
        PERFORM basalt_meta._invalid('guard version is required');
    END IF;
    IF p_expires_at IS NULL THEN
        PERFORM basalt_meta._invalid('expires_at is required');
    END IF;
    IF p_kind = 'UPGRADE' AND p_agent IS NOT NULL THEN
        PERFORM basalt_meta._invalid('an UPGRADE setup names no agent');
    END IF;
    -- pg_has_role on the oid of a role that exists: a missing name would
    -- raise instead of answering.
    IF p_kind <> 'UPGRADE' AND NOT EXISTS (SELECT 1 FROM pg_roles r
        WHERE r.rolname = p_agent AND NOT r.rolsuper AND pg_has_role(r.oid, '{{agents}}', 'USAGE')) THEN
        PERFORM basalt_meta._invalid(format('%s is not an agent role', coalesce(p_agent::text, 'null')));
    END IF;

    -- One setup at a time, so USED and SUPERSEDED see every committed row.
    PERFORM pg_advisory_xact_lock(hashtext('basalt_meta setups'));
    SELECT s.used_at INTO v_used_at FROM basalt_meta.setups s WHERE s.setup_id = p_setup_id;
    IF FOUND THEN
        PERFORM basalt_meta._setup_refused('USED', format('this setup code was already used on %s',
            to_char(v_used_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS "UTC"')));
    END IF;
    IF p_kind <> 'UPGRADE' THEN
        SELECT s.used_at INTO v_used_at FROM basalt_meta.setups s
         WHERE s.agent_role = p_agent AND s.setup_id > p_setup_id
         ORDER BY s.setup_id DESC LIMIT 1;
        IF FOUND THEN
            PERFORM basalt_meta._setup_refused('SUPERSEDED', format('a newer setup for %s already ran on %s',
                p_agent, to_char(v_used_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS "UTC"')));
        END IF;
    END IF;
    IF now() >= p_expires_at THEN
        PERFORM basalt_meta._setup_refused('EXPIRED', 'this setup code expired');
    END IF;
    v_id_at := to_timestamp((('x' || lpad(substr(v_hex, 1, c_hex_ms_len), 16, '0'))::bit(64)::bigint) / 1000.0);
    IF v_id_at > now() + c_skew THEN
        PERFORM basalt_meta._setup_refused('SETUP_ID_IN_FUTURE', 'the setup id claims a time in the future');
    END IF;
    IF p_expires_at > now() + c_lifetime + c_skew OR p_expires_at > v_id_at + c_lifetime THEN
        PERFORM basalt_meta._setup_refused('EXPIRY_TOO_FAR', 'the setup code expires too far in the future');
    END IF;

    INSERT INTO basalt_meta.setups (setup_id, kind, agent_role, guard_version, expires_at)
    VALUES (p_setup_id, p_kind, p_agent, p_guard_version, p_expires_at);
    v_actor := coalesce(p_agent, session_user);
    RETURN basalt_meta._append(v_actor, NULL, 'AGENT_SETUP', NULL, NULL, NULL, NULL, NULL, NULL,
        jsonb_build_object('setupId', p_setup_id, 'kind', p_kind, 'guardVersion', p_guard_version, 'by', session_user));
END $$;
`

const v16Views = `
-- The calling agent role's setups and every UPGRADE: the engine confirms a
-- pending setup through it.
CREATE OR REPLACE VIEW basalt_meta.agent_setups WITH (security_barrier = true) AS
    SELECT s.setup_id, s.kind, s.guard_version, s.used_at
      FROM basalt_meta.setups s
     WHERE s.agent_role = session_user OR s.kind = 'UPGRADE';

REVOKE ALL ON basalt_meta.agent_setups FROM PUBLIC;
REVOKE ALL ON FUNCTION
    basalt_meta._setup_refused(text, text),
    basalt_meta.record_setup(uuid, text, name, int, timestamptz)
FROM PUBLIC;
GRANT SELECT ON basalt_meta.agent_setups TO {{agents}};
`
