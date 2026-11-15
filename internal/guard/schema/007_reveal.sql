-- The person's reveal of redacted lines, for a revert and for a held
-- approval, with a passkey proof. These run in the agent's own
-- transaction, after any statement the agent role chose: every relation is
-- qualified and search_path is pg_catalog, pg_temp.

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

-- The full text a redacted revert line hashes (_revert_line without
-- _line_visible), with SECRET columns null and named.
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

-- The caller's own approval p_id, locked, while the person may still sign
-- it: not approved, not used, not expired. Another role's approval reads
-- like one that does not exist.
CREATE OR REPLACE FUNCTION basalt_meta._reveal_approval_lock(p_id uuid) RETURNS basalt_meta.approvals
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    a basalt_meta.approvals;
BEGIN
    SELECT * INTO a FROM basalt_meta.approvals x
     WHERE x.approval_id = p_id AND x.agent = session_user FOR UPDATE;
    IF NOT FOUND THEN
        PERFORM basalt_meta._approval_invalid('no such approval');
    END IF;
    IF a.used_by_change IS NOT NULL THEN
        PERFORM basalt_meta._approval_invalid('approval already used');
    END IF;
    IF a.approved_at IS NOT NULL THEN
        PERFORM basalt_meta._approval_invalid('approval already approved');
    END IF;
    IF a.expires_at <= pg_catalog.clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'APPROVAL_EXPIRED',
            DETAIL = pg_catalog.format('approval %s expired at %s', a.approval_id, a.expires_at);
    END IF;
    RETURN a;
END $$;

-- The rows of change p_change as _lines builds its lines, without the
-- table-privilege redaction: each row's table, the rowHash its redacted
-- line carries, and the revealed row (_reveal_row: SECRET columns null and
-- named).
CREATE OR REPLACE FUNCTION basalt_meta._reveal_lines(p_change uuid, p_assigned text[])
RETURNS TABLE (table_name text, row_hash text, revealed jsonb)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT l.table_name,
           pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
               pg_catalog.jsonb_build_array(x.key, l.old_row, x.set)::text, 'UTF8')), 'hex'),
           basalt_meta._reveal_row(l.table_oid, x.key, l.old_row, x.set)
      FROM basalt_meta.ledger l
     CROSS JOIN LATERAL (SELECT coalesce((l.detail ->> 'cascaded')::boolean, false) AS cascaded) c
     CROSS JOIN LATERAL (
         SELECT CASE WHEN l.op = 'INSERT' THEN NULL ELSE l.row_key END AS key,
                CASE WHEN l.op = 'DELETE' OR c.cascaded THEN NULL
                     ELSE coalesce((SELECT pg_catalog.jsonb_object_agg(k, l.new_row -> k)
                                      FROM pg_catalog.unnest(p_assigned) k), '{}'::jsonb)
                END AS set
     ) x
     WHERE l.change_id = p_change AND l.kind = 'ROW_CHANGE'
$$;

-- Relay of the approval page's reveal (POST …/reveal), first transaction:
-- with the person's proof and key, a ticket for one re-run preview within
-- 2 minutes. It never returns a value.
CREATE OR REPLACE FUNCTION basalt_meta.open_reveal(p_approval_id uuid, p_proof jsonb, p_reveal_key bytea) RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_window constant interval := interval '2 minutes';
    a        basalt_meta.approvals;
    v_ticket bytea := basalt_meta._revert_nonce();
    v_rows   int;
BEGIN
    PERFORM basalt_meta._require_agent();
    a := basalt_meta._reveal_approval_lock(p_approval_id);
    IF NOT basalt_meta._reveal_proven('APPROVE', a.approval_id, a.reveal_nonce, a.rows_hash, p_proof, p_reveal_key) THEN
        PERFORM basalt_meta._reveal_refused('APPROVAL_INVALID');
    END IF;
    UPDATE basalt_meta.approvals x
       SET reveal_nonce = basalt_meta._revert_nonce(),
           reveal_ticket_hash = pg_catalog.sha256(v_ticket),
           reveal_until = pg_catalog.clock_timestamp() + c_window
     WHERE x.approval_id = a.approval_id;
    SELECT pg_catalog.count(u.t)::int INTO v_rows
      FROM pg_catalog.unnest(a.lines) u(t)
     WHERE (u.t::jsonb -> 'redacted') = 'true'::jsonb;
    PERFORM basalt_meta._append(session_user, NULL, 'ROWS_REVEALED', NULL, NULL, NULL, NULL, NULL, NULL,
        pg_catalog.jsonb_build_object('kind', 'APPROVE', 'id', a.approval_id,
            'credentialId', pg_catalog.encode(basalt_meta._b64url_decode(p_proof ->> 'credentialId'), 'hex'),
            'rows', v_rows));
    RETURN v_ticket;
END $$;

-- Relay of the approval page's reveal, second transaction: in the PREVIEW
-- transaction that re-ran the held statement and recorded it with
-- finish_change, the values of the held approval's redacted lines.
CREATE OR REPLACE FUNCTION basalt_meta.reveal_approval_rows(p_approval_id uuid, p_ticket bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    a       basalt_meta.approvals;
    c       basalt_meta.changes;
    v_lines text[];
    v_rows  jsonb;
BEGIN
    PERFORM basalt_meta._require_agent();
    IF pg_catalog.current_setting('basalt.mode', true) IS DISTINCT FROM 'PREVIEW' THEN
        PERFORM basalt_meta._reveal_refused('APPROVAL_INVALID');
    END IF;
    -- The caller's own approval, read without a lock: the preview above
    -- already holds chain_head, and submit_approval takes the approval row
    -- before chain_head, so locking it here could deadlock with a
    -- signature. The checks are _reveal_approval_lock's.
    SELECT * INTO a FROM basalt_meta.approvals x
     WHERE x.approval_id = p_approval_id AND x.agent = session_user;
    IF NOT FOUND THEN
        PERFORM basalt_meta._approval_invalid('no such approval');
    END IF;
    IF a.used_by_change IS NOT NULL THEN
        PERFORM basalt_meta._approval_invalid('approval already used');
    END IF;
    IF a.approved_at IS NOT NULL THEN
        PERFORM basalt_meta._approval_invalid('approval already approved');
    END IF;
    IF a.expires_at <= pg_catalog.clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'APPROVAL_EXPIRED',
            DETAIL = pg_catalog.format('approval %s expired at %s', a.approval_id, a.expires_at);
    END IF;
    IF a.reveal_ticket_hash IS NULL OR pg_catalog.sha256(p_ticket) IS DISTINCT FROM a.reveal_ticket_hash
       OR a.reveal_until IS NULL OR a.reveal_until <= pg_catalog.clock_timestamp() THEN
        PERFORM basalt_meta._reveal_refused('APPROVAL_INVALID');
    END IF;
    -- The preview's change, as preview_lines finds it; its statement and
    -- parameters are the ones finish_change recorded in this transaction.
    SELECT * INTO c FROM basalt_meta.changes x
     WHERE x.tx = pg_catalog.pg_current_xact_id_if_assigned() AND x.agent = session_user AND x.mode = 'PREVIEW'
     ORDER BY x.stmt_ts DESC LIMIT 1;
    IF NOT FOUND OR c.statement IS DISTINCT FROM a.statement OR c.params IS DISTINCT FROM a.params
       OR c.run_id IS DISTINCT FROM a.run_id THEN
        PERFORM basalt_meta._reveal_refused('APPROVAL_INVALID');
    END IF;
    v_lines := basalt_meta._lines(c.change_id, a.assigned_columns, session_user);
    IF v_lines IS DISTINCT FROM a.lines THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'APPROVAL_INVALID', DETAIL = 'ROWS_CHANGED',
            HINT = 'the rows changed since the agent asked; this approval can no longer apply, and the agent must try the write again';
    END IF;
    WITH wanted AS (
        SELECT (u.n - 1)::int AS line, u.t::jsonb ->> 'rowHash' AS row_hash, u.t::jsonb ->> 'table' AS table_name
          FROM pg_catalog.unnest(a.lines) WITH ORDINALITY u(t, n)
         WHERE (u.t::jsonb -> 'redacted') = 'true'::jsonb
    )
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('line', w.line) || m.revealed ORDER BY w.line)
      INTO v_rows
      FROM wanted w
      JOIN LATERAL (SELECT r.revealed FROM basalt_meta._reveal_lines(c.change_id, a.assigned_columns) r
                     WHERE r.table_name = w.table_name AND r.row_hash = w.row_hash
                     LIMIT 1) m ON true;
    RETURN pg_catalog.jsonb_build_object('rows', coalesce(v_rows, '[]'::jsonb));
END $$;
