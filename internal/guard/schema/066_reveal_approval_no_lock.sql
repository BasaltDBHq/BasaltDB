-- Version 31: reveal_approval_rows reads the approval row without locking
-- it (CONTRACT.md, basalt_meta "Version 31"). Version 30 locked it FOR
-- UPDATE after the re-run preview had appended its ROW_CHANGE rows, so the
-- reveal held chain_head and then asked for the approval row, while
-- submit_approval holds the approval row and then asks for chain_head in
-- _append: a reveal racing the person's signature deadlocked (40P01).
--
-- Nothing in the second transaction needs the lock. open_reveal, which
-- still locks the row, has replaced the nonce and stored the ticket; the
-- preview rolls back and writes nothing to the approval. Every check of
-- version 30 stays: the caller's own approval, not approved, not used,
-- not expired; the ticket hash and window; PREVIEW mode; the recorded
-- statement, parameters and run; the preview's lines equal the held ones.
-- A reveal that reads the row before a signature commits gets the values
-- of a held write the person is signing; one that reads it after gets
-- APPROVAL_INVALID "approval already approved", as before.
--
-- Same signature, SECURITY DEFINER, search_path, owner and grants as
-- version 30. Idempotent.

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

REVOKE ALL ON FUNCTION basalt_meta.reveal_approval_rows(uuid, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION basalt_meta.reveal_approval_rows(uuid, bytea) TO {{agents}};
