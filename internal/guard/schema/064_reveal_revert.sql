-- Version 29 (HR-1, HR-3): the person reveals the values of a revert's
-- redacted lines with a passkey proof (CONTRACT.md, Rows hidden from the
-- agent, and basalt_meta "Version 29").
--
--   - approvals and reverts gain reveal_nonce, 16 random bytes from a
--     column default, so hold_action and prepare_revert set it unchanged;
--     the column add gives every existing row its own. agent_approvals and
--     agent_reverts list their columns, so neither shows it.
--   - reveal_nonce(kind, id): the nonce of the caller's own approval or
--     revert, for the page's reveal proof.
--   - reveal_revert_rows(id, proof, key): checks the person's proof over
--     the reveal challenge (bound to sha256 of the key the engine derives
--     from the page's reveal secret), replaces the nonce, rebuilds every
--     redacted line of the request from the ledger chains and the live rows,
--     appends ROWS_REVEALED, and returns the rows. When a row no longer
--     hashes to its line's rowHash it returns rowsChanged instead of
--     raising, so the used nonce commits either way.
--
-- The reveal functions run in the agent's own transaction, after any
-- statement the agent role chose: every relation is qualified and
-- search_path is pg_catalog, pg_temp (TestEveryGuardFunctionPutsPgTempLast).
-- Idempotent.

ALTER TABLE basalt_meta.approvals ADD COLUMN IF NOT EXISTS reveal_nonce bytea NOT NULL DEFAULT basalt_meta._revert_nonce();
ALTER TABLE basalt_meta.reverts ADD COLUMN IF NOT EXISTS reveal_nonce bytea NOT NULL DEFAULT basalt_meta._revert_nonce();

-- The one answer to every failed reveal proof, key, nonce or ticket check
-- (p_message APPROVAL_INVALID or REVERT_INVALID): the caller learns
-- nothing from which check failed.
CREATE OR REPLACE FUNCTION basalt_meta._reveal_refused(p_message text) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = p_message, DETAIL = 'REVEAL_REFUSED',
        HINT = 'showing rows hidden from the agent needs the person''s passkey on the page the engine serves';
END $$;

-- True when p_proof is the person's reveal proof for item p_id of kind
-- p_kind with key p_key: a passkey assertion, checked as submit_approval's
-- (_verify_assertion), over sha256("basalt-reveal.1\n" + kind + "\n" + id
-- + "\n" + base64url(nonce) + "\n" + hex(sha256(key)) + "\n" + rowsHash).
-- Never raises for a bad proof: any error of the check is a bad proof, so
-- every failure reads the same.
CREATE OR REPLACE FUNCTION basalt_meta._reveal_proven(
    p_kind text, p_id uuid, p_nonce bytea, p_rows_hash bytea, p_proof jsonb, p_key bytea
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_key_len constant int := 32; -- HKDF-SHA-256 output, CONTRACT.md
    v_challenge bytea;
BEGIN
    IF pg_catalog.octet_length(p_key) IS DISTINCT FROM c_key_len
       OR pg_catalog.jsonb_typeof(p_proof) IS DISTINCT FROM 'object' THEN
        RETURN false;
    END IF;
    v_challenge := pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.concat_ws(E'\n', 'basalt-reveal.1', p_kind,
        p_id::text, basalt_meta._b64url(p_nonce), pg_catalog.encode(pg_catalog.sha256(p_key), 'hex'),
        pg_catalog.encode(p_rows_hash, 'hex')), 'UTF8'));
    BEGIN
        PERFORM basalt_meta._verify_assertion(v_challenge,
            basalt_meta._b64url_decode(p_proof ->> 'credentialId'),
            basalt_meta._b64url_decode(p_proof ->> 'authenticatorData'),
            basalt_meta._b64url_decode(p_proof ->> 'clientDataJson'),
            basalt_meta._b64url_decode(p_proof ->> 'signature'));
    EXCEPTION WHEN OTHERS THEN
        RETURN false;
    END;
    RETURN true;
END $$;

-- The revealed row of a row of table p_table: {row, secretColumns?}, where
-- row is the text of jsonb_build_array(p_key, p_mid, p_set) with every
-- SECRET column (pii_columns) null wherever it appears, and secretColumns
-- names those columns (absent when there are none). p_mid is old for an
-- approval line, now for a revert line.
CREATE OR REPLACE FUNCTION basalt_meta._reveal_row(p_table oid, p_key jsonb, p_mid jsonb, p_set jsonb) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_secret text[];
    v_parts  jsonb[] := ARRAY[p_key, p_mid, p_set];
    v_null   jsonb;
BEGIN
    SELECT pg_catalog.array_agg(DISTINCT p.column_name ORDER BY p.column_name) INTO v_secret
      FROM basalt_meta.pii_columns p
      JOIN pg_catalog.pg_class c ON c.oid = p_table AND c.relname::text = p.table_name
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace AND n.nspname::text = p.table_schema
     WHERE p.class = 'SECRET'
       AND EXISTS (SELECT 1 FROM pg_catalog.unnest(v_parts) v
                    WHERE pg_catalog.jsonb_typeof(v) = 'object' AND v ? p.column_name);
    IF v_secret IS NULL THEN
        RETURN pg_catalog.jsonb_build_object('row', pg_catalog.jsonb_build_array(p_key, p_mid, p_set)::text);
    END IF;
    SELECT pg_catalog.jsonb_object_agg(s, NULL::jsonb) INTO v_null FROM pg_catalog.unnest(v_secret) s;
    SELECT pg_catalog.array_agg(CASE WHEN pg_catalog.jsonb_typeof(v) = 'object'
                                     THEN v || (SELECT coalesce(pg_catalog.jsonb_object_agg(k, NULL::jsonb), '{}'::jsonb)
                                                  FROM pg_catalog.jsonb_object_keys(v_null) k WHERE v ? k)
                                     ELSE v END ORDER BY n)
      INTO v_parts
      FROM pg_catalog.unnest(v_parts) WITH ORDINALITY u(v, n);
    RETURN pg_catalog.jsonb_build_object(
        'row', pg_catalog.jsonb_build_array(v_parts[1], v_parts[2], v_parts[3])::text,
        'secretColumns', pg_catalog.to_jsonb(v_secret));
END $$;

-- The full text a redacted revert line hashes (version 8's _revert_line
-- without _line_visible), with SECRET columns null and named.
CREATE OR REPLACE FUNCTION basalt_meta._reveal_revert_line(it basalt_meta.revert_item) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT basalt_meta._reveal_row(it.table_oid, it.key, it.now, it.set)
$$;

-- Agent, for the page's reveal proof: the reveal nonce of an approval held
-- by, or a revert prepared by, session_user. Another role's item and an
-- unknown id read alike.
CREATE OR REPLACE FUNCTION basalt_meta.reveal_nonce(p_kind text, p_id uuid) RETURNS bytea
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_nonce bytea;
BEGIN
    PERFORM basalt_meta._require_agent();
    CASE p_kind
    WHEN 'APPROVE' THEN
        SELECT a.reveal_nonce INTO v_nonce FROM basalt_meta.approvals a
         WHERE a.approval_id = p_id AND a.agent = session_user;
        IF NOT FOUND THEN
            PERFORM basalt_meta._approval_invalid('no such approval');
        END IF;
    WHEN 'REVERT' THEN
        SELECT r.reveal_nonce INTO v_nonce FROM basalt_meta.reverts r
         WHERE r.revert_id = p_id AND r.requested_by = session_user;
        IF NOT FOUND THEN
            PERFORM basalt_meta._revert_invalid('no such revert');
        END IF;
    ELSE
        RAISE EXCEPTION USING ERRCODE = 'BS008', MESSAGE = 'LEDGER_INPUT_INVALID',
            DETAIL = 'a reveal kind is APPROVE or REVERT';
    END CASE;
    RETURN v_nonce;
END $$;

-- Relay of the revert page's reveal (POST …/reveal): with the person's
-- proof and key, the values of the revert's redacted lines that the
-- request carries (every line, or a large plan's sample). Locks the revert
-- row first, so it serializes with apply_revert, rescope_revert,
-- reset_revert and reject_revert.
CREATE OR REPLACE FUNCTION basalt_meta.reveal_revert_rows(p_revert_id uuid, p_proof jsonb, p_reveal_key bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    r         basalt_meta.reverts;
    v_items   basalt_meta.revert_item[];
    v_wanted  int;
    v_rows    jsonb;
    v_changed boolean;
BEGIN
    PERFORM basalt_meta._require_agent();
    SELECT * INTO r FROM basalt_meta.reverts x
     WHERE x.revert_id = p_revert_id AND x.requested_by = session_user FOR UPDATE;
    IF NOT FOUND THEN
        PERFORM basalt_meta._revert_invalid('no such revert');
    END IF;
    IF r.applied_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_invalid('revert already applied');
    END IF;
    IF r.rejected_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_invalid('the person rejected this revert; nothing was reverted');
    END IF;
    IF r.signed_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_invalid('revert already signed');
    END IF;
    IF r.expires_at <= pg_catalog.clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'REVERT_EXPIRED',
            DETAIL = pg_catalog.format('revert %s expired at %s; prepare it again', r.revert_id, r.expires_at);
    END IF;
    IF NOT basalt_meta._reveal_proven('REVERT', r.revert_id, r.reveal_nonce, r.rows_hash, p_proof, p_reveal_key) THEN
        PERFORM basalt_meta._reveal_refused('REVERT_INVALID');
    END IF;
    UPDATE basalt_meta.reverts x SET reveal_nonce = basalt_meta._revert_nonce() WHERE x.revert_id = r.revert_id;

    -- The redacted lines of the request, by their 0-based index.
    SELECT pg_catalog.count(u.n)::int INTO v_wanted
      FROM pg_catalog.unnest(r.lines) WITH ORDINALITY u(t, n)
     WHERE (u.t::jsonb -> 'redacted') = 'true'::jsonb;

    -- Each line's row now: from its stored chain for a large plan, else
    -- from the revert's selection, as prepare_revert built it.
    IF r.batched THEN
        v_items := ARRAY(SELECT basalt_meta._revert_item(rl.chain, false)
                           FROM basalt_meta.revert_lines rl
                          WHERE rl.revert_id = r.revert_id AND rl.line = ANY (r.lines)
                            AND (rl.line::jsonb -> 'redacted') = 'true'::jsonb);
    ELSE
        v_items := ARRAY(SELECT basalt_meta._revert_item(x, false)
                           FROM basalt_meta._revert_chains(r.selection) x
                          WHERE NOT (x.first_op = 'INSERT' AND x.last_op = 'DELETE'));
    END IF;

    WITH wanted AS (
        SELECT (u.n - 1)::int AS line, u.t::jsonb ->> 'rowHash' AS row_hash, u.t::jsonb ->> 'table' AS table_name
          FROM pg_catalog.unnest(r.lines) WITH ORDINALITY u(t, n)
         WHERE (u.t::jsonb -> 'redacted') = 'true'::jsonb
    )
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('line', w.line) || basalt_meta._reveal_revert_line(m.it)
                                ORDER BY w.line)
      INTO v_rows
      FROM wanted w
      JOIN LATERAL (SELECT i AS it FROM pg_catalog.unnest(v_items) i
                     WHERE i.table_name = w.table_name
                       AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
                               pg_catalog.jsonb_build_array(i.key, i.now, i.set)::text, 'UTF8')), 'hex') = w.row_hash
                     LIMIT 1) m ON true;
    v_changed := coalesce(pg_catalog.jsonb_array_length(v_rows), 0) <> v_wanted;

    PERFORM basalt_meta._append(session_user, NULL, 'ROWS_REVEALED', NULL, NULL, NULL, NULL, NULL, NULL,
        pg_catalog.jsonb_build_object('kind', 'REVERT', 'id', r.revert_id,
            'credentialId', pg_catalog.encode(basalt_meta._b64url_decode(p_proof ->> 'credentialId'), 'hex'),
            'rows', v_wanted)
        || CASE WHEN v_changed THEN pg_catalog.jsonb_build_object('rowsChanged', true) ELSE '{}'::jsonb END);
    IF v_changed THEN
        RETURN pg_catalog.jsonb_build_object('rowsChanged', true);
    END IF;
    RETURN pg_catalog.jsonb_build_object('rows', coalesce(v_rows, '[]'::jsonb));
END $$;

REVOKE ALL ON FUNCTION
    basalt_meta._reveal_refused(text),
    basalt_meta._reveal_proven(text, uuid, bytea, bytea, jsonb, bytea),
    basalt_meta._reveal_row(oid, jsonb, jsonb, jsonb),
    basalt_meta._reveal_revert_line(basalt_meta.revert_item),
    basalt_meta.reveal_nonce(text, uuid),
    basalt_meta.reveal_revert_rows(uuid, jsonb, bytea)
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    basalt_meta.reveal_nonce(text, uuid),
    basalt_meta.reveal_revert_rows(uuid, jsonb, bytea)
TO {{agents}};
