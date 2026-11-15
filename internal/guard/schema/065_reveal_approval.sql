-- Version 30 (HR-1, HR-2, HR-3): the person reveals the values of a held
-- approval's redacted lines (CONTRACT.md, Rows hidden from the agent, and
-- basalt_meta "Version 30"). The values exist only while a preview of the
-- held statement is open, and a PREVIEW transaction cannot commit, so a
-- reveal takes two transactions:
--
--   - open_reveal(id, proof, key) checks the person's proof over the
--     reveal challenge (version 29's _reveal_proven, kind APPROVE),
--     replaces the nonce, appends ROWS_REVEALED, and returns a fresh ticket
--     good for 2 minutes; only its sha256 is stored.
--   - In a PREVIEW transaction that re-ran the held statement and recorded
--     it with finish_change, as at an apply, reveal_approval_rows(id,
--     ticket) checks the ticket and that the preview change's recorded
--     statement, parameters and run are the held ones (as _commit_approval
--     checks an apply), then that the preview's lines (redacted for
--     session_user) equal the held lines, or ROWS_CHANGED. It returns the
--     redacted lines' rows through _reveal_lines, SECRET columns null and
--     named. The preview rolls back, so nothing outlasts it.
--
-- These run in the agent's own transaction, after its statement: every
-- relation is qualified and search_path is pg_catalog, pg_temp.
-- Idempotent.

ALTER TABLE basalt_meta.approvals
    ADD COLUMN IF NOT EXISTS reveal_ticket_hash bytea,
    ADD COLUMN IF NOT EXISTS reveal_until timestamptz;

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
    a := basalt_meta._reveal_approval_lock(p_approval_id);
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

REVOKE ALL ON FUNCTION
    basalt_meta._reveal_approval_lock(uuid),
    basalt_meta._reveal_lines(uuid, text[]),
    basalt_meta.open_reveal(uuid, jsonb, bytea),
    basalt_meta.reveal_approval_rows(uuid, bytea)
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    basalt_meta.open_reveal(uuid, jsonb, bytea),
    basalt_meta.reveal_approval_rows(uuid, bytea)
TO {{agents}};
