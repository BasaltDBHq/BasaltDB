-- Read-gate spike. Loaded by the setup admin (a non-superuser with
-- CREATEROLE) after the P-256 helpers (_num .. _p256_verify), which the
-- test reads straight out of guard/schema/005_approvals.sql.
--
-- A ticket is the exact payload text Vault signed (JSON with agent,
-- engine_key_id, expires_at as unix seconds, nonce) plus the raw ECDSA
-- (r, s) over sha256(payload). The payload is verified as sent and parsed
-- only afterwards.

CREATE TABLE basalt_meta.ticket_keys (
    key_id     text PRIMARY KEY,
    qx         numeric NOT NULL,
    qy         numeric NOT NULL,
    revoked_at timestamptz
);

CREATE TABLE basalt_meta.engine_keys (
    key_id     text PRIMARY KEY,
    revoked_at timestamptz
);

-- Every ticket ever opened: the nonce makes a ticket single use.
CREATE TABLE basalt_meta.tickets (
    nonce         text PRIMARY KEY,
    agent         text NOT NULL,
    engine_key_id text NOT NULL,
    expires_at    timestamptz NOT NULL,
    opened_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    role_name     text,
    revoked_at    timestamptz
);

CREATE FUNCTION basalt_meta._ticket_invalid(p_detail text) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'BS901', MESSAGE = 'TICKET_INVALID', DETAIL = p_detail;
END $$;

CREATE FUNCTION basalt_meta._check_ticket(p_payload text, p_r numeric, p_s numeric, p_agent text)
RETURNS basalt_meta.tickets
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_max_life constant interval := interval '15 minutes';
    k   basalt_meta.ticket_keys;
    j   jsonb;
    exp timestamptz;
    t   basalt_meta.tickets;
BEGIN
    IF p_payload IS NULL OR p_r IS NULL OR p_s IS NULL OR octet_length(p_payload) > 1024 THEN
        PERFORM basalt_meta._ticket_invalid('missing or oversized ticket');
    END IF;
    SELECT * INTO k FROM basalt_meta.ticket_keys WHERE key_id = 'vault' AND revoked_at IS NULL;
    IF NOT FOUND THEN
        PERFORM basalt_meta._ticket_invalid('no ticket key installed');
    END IF;
    IF NOT basalt_meta._p256_verify(sha256(convert_to(p_payload, 'UTF8')), p_r, p_s, k.qx, k.qy) THEN
        PERFORM basalt_meta._ticket_invalid('bad signature');
    END IF;
    j := p_payload::jsonb;
    IF j ->> 'agent' IS DISTINCT FROM p_agent THEN
        PERFORM basalt_meta._ticket_invalid('ticket is for another agent');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM basalt_meta.engine_keys e
                    WHERE e.key_id = j ->> 'engine_key_id' AND e.revoked_at IS NULL) THEN
        PERFORM basalt_meta._ticket_invalid('engine key unknown or revoked');
    END IF;
    exp := to_timestamp((j ->> 'expires_at')::bigint);
    IF exp <= clock_timestamp() THEN
        PERFORM basalt_meta._ticket_invalid('ticket expired');
    END IF;
    IF exp > clock_timestamp() + c_max_life THEN
        PERFORM basalt_meta._ticket_invalid('ticket lifetime too long');
    END IF;
    INSERT INTO basalt_meta.tickets (nonce, agent, engine_key_id, expires_at)
    VALUES (j ->> 'nonce', p_agent, j ->> 'engine_key_id', exp)
    ON CONFLICT (nonce) DO NOTHING
    RETURNING * INTO t;
    IF t.nonce IS NULL THEN
        PERFORM basalt_meta._ticket_invalid('ticket already used');
    END IF;
    RETURN t;
END $$;

CREATE FUNCTION basalt_meta._random_secret() RETURNS text
LANGUAGE sql VOLATILE SET search_path = pg_catalog, pg_temp AS $$
    SELECT encode(sha256(convert_to(gen_random_uuid()::text || gen_random_uuid()::text, 'UTF8')), 'hex')
$$;

------------------------------------------------------------------------
-- Candidate A: short-lived login.
-- agent_gate holds the stored password and can only call open_read_a.
-- agent_reader (member of basalt_reads, which holds the grants) gets a
-- fresh random password valid until the ticket expires.
------------------------------------------------------------------------
CREATE FUNCTION basalt_meta.open_read_a(p_payload text, p_r numeric, p_s numeric) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    t  basalt_meta.tickets;
    pw text := basalt_meta._random_secret();
BEGIN
    t := basalt_meta._check_ticket(p_payload, p_r, p_s, 'agent_a');
    EXECUTE format('ALTER ROLE agent_reader PASSWORD %L VALID UNTIL %L', pw, t.expires_at::text);
    UPDATE basalt_meta.tickets SET role_name = 'agent_reader' WHERE nonce = t.nonce;
    RETURN pw;
END $$;

-- A2: one login role per ticket, so a revoke or the expiry sweep can drop
-- its membership in basalt_reads without touching other tickets.
CREATE FUNCTION basalt_meta.open_read_a2(p_payload text, p_r numeric, p_s numeric) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    t    basalt_meta.tickets;
    pw   text := basalt_meta._random_secret();
    rname text;
BEGIN
    t := basalt_meta._check_ticket(p_payload, p_r, p_s, 'agent_a');
    rname := 'basalt_r_' || left(md5(t.nonce), 12);
    EXECUTE format('CREATE ROLE %I LOGIN PASSWORD %L VALID UNTIL %L IN ROLE basalt_reads',
                   rname, pw, t.expires_at::text);
    UPDATE basalt_meta.tickets SET role_name = rname WHERE nonce = t.nonce;
    RETURN jsonb_build_object('user', rname, 'password', pw);
END $$;

-- Revoke for A: no password, and end the open sessions.
CREATE FUNCTION basalt_meta.revoke_reads_a() RETURNS int
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE n int;
BEGIN
    ALTER ROLE agent_reader PASSWORD NULL;
    SELECT count(*) INTO n FROM pg_stat_activity a
     WHERE a.usename = 'agent_reader' AND pg_terminate_backend(a.pid);
    RETURN n;
END $$;

-- Revoke or expire one A2 ticket: drop its grants membership (checked at
-- every query, so open sessions lose access at once) and its login.
CREATE FUNCTION basalt_meta.revoke_ticket_a2(p_nonce text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE rname text;
BEGIN
    UPDATE basalt_meta.tickets SET revoked_at = clock_timestamp()
     WHERE nonce = p_nonce RETURNING role_name INTO rname;
    EXECUTE format('REVOKE basalt_reads FROM %I', rname);
    EXECUTE format('ALTER ROLE %I NOLOGIN PASSWORD NULL', rname);
END $$;

CREATE FUNCTION basalt_meta.sweep_a2() RETURNS int
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r record; n int := 0;
BEGIN
    FOR r IN SELECT nonce FROM basalt_meta.tickets
              WHERE role_name LIKE 'basalt_r_%' AND revoked_at IS NULL AND expires_at <= clock_timestamp() LOOP
        PERFORM basalt_meta.revoke_ticket_a2(r.nonce);
        n := n + 1;
    END LOOP;
    RETURN n;
END $$;

------------------------------------------------------------------------
-- Candidate B: session check in row-level security.
-- agent_b keeps SELECT; a restrictive policy TO agent_b allows rows only
-- while this backend has a live session row, bound to pid plus a random
-- token kept in a backend-local setting (so a reused pid finds no token).
------------------------------------------------------------------------
CREATE TABLE basalt_meta.sessions (
    pid        int NOT NULL,
    token      text NOT NULL,
    nonce      text NOT NULL REFERENCES basalt_meta.tickets (nonce),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    PRIMARY KEY (pid, token)
);

CREATE FUNCTION basalt_meta.open_read_b(p_payload text, p_r numeric, p_s numeric) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    t   basalt_meta.tickets;
    tok text := basalt_meta._random_secret();
BEGIN
    t := basalt_meta._check_ticket(p_payload, p_r, p_s, 'agent_b');
    INSERT INTO basalt_meta.sessions (pid, token, nonce, expires_at)
    VALUES (pg_backend_pid(), tok, t.nonce, t.expires_at);
    PERFORM set_config('basalt.read_token', tok, false);
    RETURN t.expires_at;
END $$;

CREATE FUNCTION basalt_meta.read_open() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (
        SELECT 1 FROM basalt_meta.sessions s
         WHERE s.pid = pg_backend_pid()
           AND s.token = current_setting('basalt.read_token', true)
           AND s.revoked_at IS NULL
           AND s.expires_at > statement_timestamp())
$$;

-- The naive pid-only check, kept only to show what pid reuse would do.
CREATE FUNCTION basalt_meta.read_open_pid_only() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (
        SELECT 1 FROM basalt_meta.sessions s
         WHERE s.pid = pg_backend_pid() AND s.revoked_at IS NULL
           AND s.expires_at > statement_timestamp())
$$;

CREATE FUNCTION basalt_meta.revoke_ticket_b(p_nonce text) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    UPDATE basalt_meta.sessions SET revoked_at = clock_timestamp() WHERE nonce = p_nonce;
    UPDATE basalt_meta.tickets SET revoked_at = clock_timestamp() WHERE nonce = p_nonce;
$$;

------------------------------------------------------------------------
-- Privileges: nothing in basalt_meta is open to PUBLIC.
------------------------------------------------------------------------
REVOKE ALL ON SCHEMA basalt_meta FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA basalt_meta FROM PUBLIC;
GRANT USAGE ON SCHEMA basalt_meta TO agent_gate, agent_b;
GRANT EXECUTE ON FUNCTION basalt_meta.open_read_a(text, numeric, numeric) TO agent_gate;
GRANT EXECUTE ON FUNCTION basalt_meta.open_read_a2(text, numeric, numeric) TO agent_gate;
GRANT EXECUTE ON FUNCTION basalt_meta.open_read_b(text, numeric, numeric) TO agent_b;
GRANT EXECUTE ON FUNCTION basalt_meta.read_open() TO agent_b;
GRANT EXECUTE ON FUNCTION basalt_meta.read_open_pid_only() TO agent_b;
