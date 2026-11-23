-- Version 8: the engine address is removed with the direct transport. An
-- engine record is its key, when it was recorded and whether it is
-- revoked: record_engine takes the key alone, the url column and its
-- grammar check go, and revoke_engine's ledger detail no longer names an
-- address. Ledger rows written before keep their url as they are.

DROP FUNCTION IF EXISTS basalt_meta.record_engine(bytea, text);
DROP FUNCTION IF EXISTS basalt_meta._engine_url_ok(text);

-- The agents' view names the column, so it goes first and comes back
-- without it.
DROP VIEW IF EXISTS basalt_meta.agent_engines;
ALTER TABLE basalt_meta.engines DROP COLUMN IF EXISTS url;

-- Every engine row an agent role may read: keys are not secrets, and the
-- engine reads its own row here.
CREATE VIEW basalt_meta.agent_engines WITH (security_barrier = true) AS
    SELECT e.engine_id, e.public_key, e.recorded_at, e.revoked_at
      FROM basalt_meta.engines e;
REVOKE ALL ON basalt_meta.agent_engines FROM PUBLIC;
GRANT SELECT ON basalt_meta.agent_engines TO {{agents}};

-- Admin only (basalt init --setup-code): record an engine's signing key.
-- Returns the engine id. Appends ENGINE_RECORDED when it inserts the key,
-- nothing when the key was recorded already.
CREATE OR REPLACE FUNCTION basalt_meta.record_engine(p_public_key bytea) RETURNS text
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
    v_id := basalt_meta._engine_id(p_public_key);
    INSERT INTO basalt_meta.engines (engine_id, public_key, recorded_at, recorded_by, updated_at)
    VALUES (v_id, p_public_key, v_now, session_user, v_now)
    ON CONFLICT (engine_id) DO NOTHING;
    IF FOUND THEN
        PERFORM basalt_meta._append(session_user, NULL, 'ENGINE_RECORDED', NULL, NULL, NULL, NULL, NULL, NULL,
            pg_catalog.jsonb_build_object('engineId', v_id, 'by', session_user));
        RETURN v_id;
    END IF;
    -- Recorded already, by an earlier setup or a transaction that won the
    -- race: refused when revoked, else nothing changes.
    SELECT * INTO v_row FROM basalt_meta.engines e WHERE e.engine_id = v_id FOR UPDATE;
    IF v_row.revoked_at IS NOT NULL THEN
        PERFORM basalt_meta._engine_refused('ENGINE_REVOKED',
            pg_catalog.format('engine %s was revoked on %s; a revoked engine is never recorded again', v_id,
                pg_catalog.to_char(v_row.revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS "UTC"')));
    END IF;
    RETURN v_id;
END $$;
REVOKE ALL ON FUNCTION basalt_meta.record_engine(bytea) FROM PUBLIC;

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
        pg_catalog.jsonb_build_object('engineId', p_engine_id, 'by', session_user, 'remaining', v_remaining));
    RETURN v_remaining;
END $$;
