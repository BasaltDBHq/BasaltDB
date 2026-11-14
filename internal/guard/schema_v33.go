package guard

// Version 33 (M4.1, owner decisions VC-21 and CO-18): engine keys and the
// pinned address (CONTRACT.md, basalt_meta "Version 33" and "Direct
// transport"). The person's computer records the engine's signing key with
// the address its tunnel publishes, and the person can revoke an engine.
// Written only by the admin; an agent role reads the rows through
// agent_engines, so the bot can neither record a key nor move an address.
//
// The engine id is computed here from the key, never taken as given, and a
// revoked key is never recorded again. Rows are never deleted.
// Non-breaking: an engine on an older guard reports engineRecord UNKNOWN and
// serves everything else as before. Idempotent.
const v33Tables = `
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
`

const v33Functions = `
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
`

const v33Views = `
-- Every engine row an agent role may read: keys and addresses are not
-- secrets, and the engine reads its own row here.
CREATE OR REPLACE VIEW basalt_meta.agent_engines WITH (security_barrier = true) AS
    SELECT e.engine_id, e.public_key, e.url, e.recorded_at, e.revoked_at
      FROM basalt_meta.engines e;
REVOKE ALL ON basalt_meta.agent_engines FROM PUBLIC;
REVOKE ALL ON FUNCTION
    basalt_meta._engine_url_ok(text),
    basalt_meta._engine_id(bytea),
    basalt_meta._engine_refused(text, text),
    basalt_meta.record_engine(bytea, text),
    basalt_meta.revoke_engine(text)
FROM PUBLIC;
GRANT SELECT ON basalt_meta.agent_engines TO {{agents}};
`
