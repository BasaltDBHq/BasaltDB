-- Setups recorded by basalt init --setup-code, engine keys and their
-- pinned address, and reinstalls on the record.

CREATE OR REPLACE FUNCTION basalt_meta._setup_refused(p_reason text, p_hint text) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'BS010', MESSAGE = 'SETUP_REFUSED', DETAIL = p_reason, HINT = p_hint;
END $$;

-- Admin only (basalt init --setup-code): record a setup code in the
-- install's transaction and append its AGENT_SETUP ledger row. Refuses a
-- code already used, one older than the agent's latest recorded setup
-- (UUIDv7 ids are time-ordered), and one whose times the database's clock
-- (clock_timestamp(), read after the lock) rejects. The agent must be a
-- login role in the agents group, not a superuser, without CREATEROLE, and
-- not the group itself. Returns the ledger seq.
CREATE OR REPLACE FUNCTION basalt_meta.record_setup(
    p_setup_id uuid, p_kind text, p_agent name, p_guard_version int, p_expires_at timestamptz
) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_skew       constant interval := interval '5 minutes';
    c_lifetime   constant interval := interval '24 hours';
    c_hex_ms_len constant int      := 12; -- the first 48 bits of a UUIDv7, in hex
    c_version    constant int      := 15; -- 1-based position of the version digit in uuid text
    v_hex      text := replace(p_setup_id::text, '-', '');
    v_id_at    timestamptz;
    v_used_at  timestamptz;
    v_now      timestamptz;
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
    IF p_kind <> 'UPGRADE' AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
        WHERE r.rolname = p_agent AND r.rolname <> '{{agents}}'
          AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreaterole
          AND pg_has_role(r.oid, '{{agents}}', 'USAGE')) THEN
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
    -- The time now, not the transaction's start: the person may have
    -- waited inside the transaction, and the lock above may have waited.
    v_now := clock_timestamp();
    IF v_now >= p_expires_at THEN
        PERFORM basalt_meta._setup_refused('EXPIRED', 'this setup code expired');
    END IF;
    v_id_at := to_timestamp((('x' || lpad(substr(v_hex, 1, c_hex_ms_len), 16, '0'))::bit(64)::bigint) / 1000.0);
    IF v_id_at > v_now + c_skew THEN
        PERFORM basalt_meta._setup_refused('SETUP_ID_IN_FUTURE', 'the setup id claims a time in the future');
    END IF;
    IF p_expires_at > v_now + c_lifetime + c_skew OR p_expires_at > v_id_at + c_lifetime THEN
        PERFORM basalt_meta._setup_refused('EXPIRY_TOO_FAR', 'the setup code expires too far in the future');
    END IF;

    INSERT INTO basalt_meta.setups (setup_id, kind, agent_role, guard_version, expires_at)
    VALUES (p_setup_id, p_kind, p_agent, p_guard_version, p_expires_at);
    v_actor := coalesce(p_agent, session_user);
    RETURN basalt_meta._append(v_actor, NULL, 'AGENT_SETUP', NULL, NULL, NULL, NULL, NULL, NULL,
        jsonb_build_object('setupId', p_setup_id, 'kind', p_kind, 'guardVersion', p_guard_version, 'by', session_user));
END $$;

-- An engine address (CONTRACT.md, Direct transport, the grammar): https,
-- an ASCII lowercase DNS name of two or more labels whose last starts with
-- a letter (so nothing a browser reads as an IP), no trailing dot, not
-- localhost, .local, .internal, .home.arpa or basaltvault.app names, a
-- decimal port 1 to 65535 without a leading zero and other than 443, no
-- user part, path, query or fragment: only the written form, which laptop
-- init makes (it drops a trailing slash). NULL is no address.
CREATE OR REPLACE FUNCTION basalt_meta._engine_url_ok(p_url text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_host_max  constant int := 253;
    c_port_max  constant int := 65535;
    c_https     constant int := 443;
    m    text[];
    host text;
    port int;
BEGIN
    IF p_url IS NULL THEN
        RETURN true;
    END IF;
    m := pg_catalog.regexp_match(p_url,
        '^https://((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?)(?::([1-9][0-9]{0,4}))?$');
    IF m IS NULL THEN
        RETURN false;
    END IF;
    host := m[1];
    IF pg_catalog.length(host) > c_host_max
       OR host ~ '(^|\.)localhost$' OR host ~ '\.(local|internal|home\.arpa)$'
       OR host ~ '(^|\.)basaltvault\.app$' THEN
        RETURN false;
    END IF;
    IF m[2] IS NOT NULL THEN
        port := m[2]::int;
        IF port > c_port_max OR port = c_https THEN
            RETURN false;
        END IF;
    END IF;
    RETURN true;
END $$;

-- The engine id of a signing key (CONTRACT.md, Engine keys): base64url of
-- the first 16 bytes of sha256 of the SPKI DER.
CREATE OR REPLACE FUNCTION basalt_meta._engine_id(p_key bytea) RETURNS text
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
    SELECT basalt_meta._b64url(pg_catalog.substring(pg_catalog.sha256(p_key), 1, 16))
$$;

CREATE OR REPLACE FUNCTION basalt_meta._engine_refused(p_detail text, p_hint text) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'BS008', MESSAGE = 'LEDGER_INPUT_INVALID', DETAIL = p_detail, HINT = p_hint;
END $$;

-- Admin only (basalt init --setup-code): record an engine's signing key,
-- with the address the person gave or NULL to keep the recorded one.
-- Returns the engine id. Appends ENGINE_RECORDED when it inserts a key or
-- changes its address, nothing when nothing changed.
CREATE OR REPLACE FUNCTION basalt_meta.record_engine(p_public_key bytea, p_url text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    -- SubjectPublicKeyInfo of id-ecPublicKey on prime256v1, then 0x04
    -- (an uncompressed point): 27 bytes, then X and Y of 32 bytes each.
    c_spki_prefix constant bytea := '\x3059301306072a8648ce3d020106082a8648ce3d03010703420004'::bytea;
    c_prefix_len  constant int   := 27;
    c_coord_len   constant int   := 32;
    c_key_len     constant int   := 91;
    v_id   text;
    v_row  basalt_meta.engines;
    v_now  timestamptz := pg_catalog.clock_timestamp();
BEGIN
    IF p_public_key IS NULL OR pg_catalog.octet_length(p_public_key) <> c_key_len
       OR pg_catalog.substring(p_public_key, 1, c_prefix_len) <> c_spki_prefix
       OR NOT basalt_meta._p256_on_curve(
              basalt_meta._num(pg_catalog.substring(p_public_key, c_prefix_len + 1, c_coord_len)),
              basalt_meta._num(pg_catalog.substring(p_public_key, c_prefix_len + c_coord_len + 1, c_coord_len))) THEN
        PERFORM basalt_meta._engine_refused('ENGINE_KEY', 'the engine key must be a P-256 SubjectPublicKeyInfo with an uncompressed point on the curve');
    END IF;
    IF NOT basalt_meta._engine_url_ok(p_url) THEN
        PERFORM basalt_meta._engine_refused('ENGINE_URL',
            'the engine address must be https://<host>[:<port>]: a DNS name (not an IP address, localhost or basaltvault.app), no path, query or user part');
    END IF;
    v_id := basalt_meta._engine_id(p_public_key);
    SELECT * INTO v_row FROM basalt_meta.engines e WHERE e.engine_id = v_id FOR UPDATE;
    IF FOUND AND v_row.revoked_at IS NOT NULL THEN
        PERFORM basalt_meta._engine_refused('ENGINE_REVOKED',
            pg_catalog.format('engine %s was revoked on %s; a revoked engine is never recorded again', v_id,
                pg_catalog.to_char(v_row.revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS "UTC"')));
    END IF;
    IF NOT FOUND THEN
        INSERT INTO basalt_meta.engines (engine_id, public_key, url, recorded_at, recorded_by, updated_at)
        VALUES (v_id, p_public_key, p_url, v_now, session_user, v_now)
        ON CONFLICT (engine_id) DO NOTHING;
        IF NOT FOUND THEN
            -- Another transaction recorded it first: take its row and go on
            -- as for a key already recorded.
            SELECT * INTO v_row FROM basalt_meta.engines e WHERE e.engine_id = v_id FOR UPDATE;
            IF v_row.revoked_at IS NOT NULL THEN
                PERFORM basalt_meta._engine_refused('ENGINE_REVOKED', 'this engine was revoked; a revoked engine is never recorded again');
            END IF;
        ELSE
            PERFORM basalt_meta._append(session_user, NULL, 'ENGINE_RECORDED', NULL, NULL, NULL, NULL, NULL, NULL,
                pg_catalog.jsonb_build_object('engineId', v_id, 'url', p_url, 'by', session_user));
            RETURN v_id;
        END IF;
    END IF;
    IF p_url IS NULL OR p_url IS NOT DISTINCT FROM v_row.url THEN
        RETURN v_id;
    END IF;
    UPDATE basalt_meta.engines e SET url = p_url, updated_at = v_now WHERE e.engine_id = v_id;
    PERFORM basalt_meta._append(session_user, NULL, 'ENGINE_RECORDED', NULL, NULL, NULL, NULL, NULL, NULL,
        pg_catalog.jsonb_build_object('engineId', v_id, 'url', p_url, 'previousUrl', v_row.url, 'by', session_user));
    RETURN v_id;
END $$;

-- Admin only (basalt engine revoke, basalt init --setup-code): revoke an
-- engine and return how many engines remain not revoked. Appends
-- ENGINE_REVOKED. An unknown and an already revoked id are refused alike.
CREATE OR REPLACE FUNCTION basalt_meta.revoke_engine(p_engine_id text) RETURNS int
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_row       basalt_meta.engines;
    v_remaining int;
BEGIN
    SELECT * INTO v_row FROM basalt_meta.engines e WHERE e.engine_id = p_engine_id FOR UPDATE;
    IF NOT FOUND OR v_row.revoked_at IS NOT NULL THEN
        PERFORM basalt_meta._engine_refused('ENGINE_UNKNOWN', 'no engine recorded and not revoked with this id');
    END IF;
    UPDATE basalt_meta.engines e SET revoked_at = pg_catalog.clock_timestamp(), revoked_by = session_user
     WHERE e.engine_id = p_engine_id;
    SELECT pg_catalog.count(e.engine_id)::int INTO v_remaining FROM basalt_meta.engines e WHERE e.revoked_at IS NULL;
    PERFORM basalt_meta._append(session_user, NULL, 'ENGINE_REVOKED', NULL, NULL, NULL, NULL, NULL, NULL,
        pg_catalog.jsonb_build_object('engineId', p_engine_id, 'url', v_row.url, 'by', session_user, 'remaining', v_remaining));
    RETURN v_remaining;
END $$;

-- An agent reports that the chain head it pinned (p_seq, p_hash) was
-- verified on another install (p_install), before it sets that pin aside.
-- Appends PIN_SET_ASIDE with the install's row copied in, so the row stands
-- on its own; the install fields are absent when installs has no row for
-- the current install (basalt_meta was recreated or restored outside the
-- install). Returns false, appending nothing, for a report this role
-- already made. The chain head's row lock serializes the check with the
-- append.
CREATE OR REPLACE FUNCTION basalt_meta.record_pin_set_aside(p_seq bigint, p_hash bytea, p_install oid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_hash_len constant int := 32;
    v_install  oid;
    v_row      basalt_meta.installs;
    v_detail   jsonb;
BEGIN
    IF p_seq IS NULL OR p_seq < 0 OR p_hash IS NULL OR pg_catalog.octet_length(p_hash) <> c_hash_len
       OR p_install IS NULL THEN
        PERFORM basalt_meta._invalid('PIN_SHAPE');
    END IF;
    SELECT n.oid INTO v_install FROM pg_catalog.pg_namespace n WHERE n.nspname = 'basalt_meta';
    IF p_install = v_install THEN
        PERFORM basalt_meta._invalid('PIN_SAME_INSTALL');
    END IF;
    PERFORM 1 FROM basalt_meta.chain_head h WHERE h.id FOR UPDATE;
    IF EXISTS (SELECT 1 FROM basalt_meta.ledger l
                WHERE l.agent = session_user AND l.kind = 'PIN_SET_ASIDE'
                  AND l.detail->>'pinnedInstall' = p_install::text
                  AND l.detail->>'pinnedSeq' = p_seq::text
                  AND l.detail->>'pinnedHash' = pg_catalog.encode(p_hash, 'hex')) THEN
        RETURN false;
    END IF;
    v_detail := pg_catalog.jsonb_build_object('pinnedSeq', p_seq, 'pinnedHash', pg_catalog.encode(p_hash, 'hex'),
        'pinnedInstall', p_install::bigint, 'install', v_install::bigint);
    SELECT * INTO v_row FROM basalt_meta.installs i WHERE i.install = v_install;
    IF FOUND THEN
        v_detail := v_detail || pg_catalog.jsonb_build_object(
            'installedAt', pg_catalog.to_char(v_row.installed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
            'installedBy', v_row.installed_by);
        IF v_row.vault_user IS NOT NULL THEN
            v_detail := v_detail || pg_catalog.jsonb_build_object('vaultUser', v_row.vault_user);
        END IF;
    END IF;
    PERFORM basalt_meta._append(session_user, NULL, 'PIN_SET_ASIDE', NULL, NULL, NULL, NULL, NULL, NULL, v_detail);
    RETURN true;
END $$;

-- Whether a pinned head is still on the current chain: the row at p_seq,
-- after the anchor, exists, holds p_hash and recomputes to it, or p_seq is
-- the anchor's seq and the anchor's hash is p_hash. False for a pin before
-- the anchor, which verify_chain_from and check_head accept as verifying
-- from it. Agents cannot read chain_anchor or other agents' rows: this is
-- how a witness tells "my pinned entry is still here" from "the anchor
-- moved past it". Reads only; returns no row data.
CREATE OR REPLACE FUNCTION basalt_meta.pin_on_chain(p_seq bigint, p_hash bytea) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    a basalt_meta.chain_anchor;
    l basalt_meta.ledger;
BEGIN
    IF p_seq IS NULL OR p_hash IS NULL THEN
        RETURN false;
    END IF;
    SELECT * INTO a FROM basalt_meta.chain_anchor x WHERE x.id;
    IF p_seq = a.seq THEN
        RETURN a.hash = p_hash;
    END IF;
    IF p_seq < a.seq THEN
        RETURN false;
    END IF;
    SELECT * INTO l FROM basalt_meta.ledger x WHERE x.seq = p_seq;
    RETURN FOUND AND l.hash = p_hash AND l.hash = pg_catalog.sha256(l.prev_hash || basalt_meta._canonical(l));
END $$;
