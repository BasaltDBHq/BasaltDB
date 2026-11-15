-- The agent views of reverts and revert lines, and retention of plan
-- lines.

-- Retention (version 7) plus a plan's lines: their text and chain are
-- values (30 days); the rows go with their revert after 1 year.
CREATE OR REPLACE FUNCTION basalt_meta._prune(p_now timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    c_values_ttl constant interval := interval '30 days';
    c_meta_ttl   constant interval := interval '1 year';
    v_values  bigint := 0;
    v_rows    bigint := 0;
    v_expired bigint := 0;
    v_cut     bigint;
BEGIN
    UPDATE basalt_meta.changes c SET status = 'APPROVAL_EXPIRED'
      FROM basalt_meta.approvals a
     WHERE a.held_change = c.change_id AND c.status = 'APPROVAL_PENDING'
       AND a.used_by_change IS NULL AND a.expires_at <= p_now;
    GET DIAGNOSTICS v_expired = ROW_COUNT;

    UPDATE basalt_meta.ledger SET old_row = NULL, new_row = NULL, values_pruned = true
     WHERE NOT values_pruned AND at < p_now - c_values_ttl AND (old_row IS NOT NULL OR new_row IS NOT NULL);
    GET DIAGNOSTICS v_values = ROW_COUNT;
    UPDATE basalt_meta.changes SET params = NULL WHERE params IS NOT NULL AND at < p_now - c_values_ttl;
    UPDATE basalt_meta.approvals SET params = NULL, lines = NULL, binding_text = NULL, statement = NULL
     WHERE created_at < p_now - c_values_ttl AND (lines IS NOT NULL OR binding_text IS NOT NULL);
    UPDATE basalt_meta.reverts SET lines = NULL, binding_text = NULL
     WHERE created_at < p_now - c_values_ttl AND (lines IS NOT NULL OR binding_text IS NOT NULL);
    UPDATE basalt_meta.revert_lines l SET line = NULL, chain = NULL
      FROM basalt_meta.reverts r
     WHERE r.revert_id = l.revert_id AND r.created_at < p_now - c_values_ttl AND l.line IS NOT NULL;

    SELECT max(seq) INTO v_cut FROM basalt_meta.ledger WHERE at < p_now - c_meta_ttl;
    IF v_cut IS NOT NULL THEN
        UPDATE basalt_meta.chain_anchor a SET seq = l.seq, hash = l.hash
          FROM basalt_meta.ledger l WHERE a.id AND l.seq = v_cut;
        DELETE FROM basalt_meta.ledger WHERE seq <= v_cut;
        GET DIAGNOSTICS v_rows = ROW_COUNT;
        DELETE FROM basalt_meta.changes WHERE at < p_now - c_meta_ttl;
        DELETE FROM basalt_meta.runs WHERE started_at < p_now - c_meta_ttl;
        DELETE FROM basalt_meta.approvals WHERE created_at < p_now - c_meta_ttl;
        DELETE FROM basalt_meta.reverts WHERE created_at < p_now - c_meta_ttl;
    END IF;

    IF v_values + v_rows > 0 THEN
        PERFORM basalt_meta._append(session_user, NULL, 'PRUNED', NULL, NULL, NULL, NULL, NULL, NULL,
            jsonb_build_object('valuesPruned', v_values, 'rowsDeleted', v_rows));
    END IF;
    RETURN jsonb_build_object('valuesPruned', v_values, 'rowsDeleted', v_rows, 'approvalsExpired', v_expired);
END $$;

-- The reverts the calling role prepared (version 6), with a batched plan's
-- signature, window and progress. APPLYING: signed, lines pending, within
-- the window; EXPIRED: not signed in time, or not finished in time.
CREATE OR REPLACE VIEW basalt_meta.agent_reverts WITH (security_barrier = true) AS
    SELECT r.revert_id, r.scope, r.scope_id, r.agents, r.intent, r.rows, r.skipped,
           CASE WHEN r.applied_at IS NOT NULL THEN 'APPLIED'
                WHEN r.signed_at IS NOT NULL AND r.apply_by > pg_catalog.now() THEN 'APPLYING'
                WHEN r.signed_at IS NOT NULL THEN 'EXPIRED'
                WHEN r.expires_at <= pg_catalog.now() THEN 'EXPIRED'
                ELSE 'PENDING' END AS status,
           r.created_at, r.expires_at, r.applied_at, r.change_id, r.binding_text, r.lines,
           r.batched, r.signed_at, r.apply_by, r.batches, p.restored, p.skipped AS skipped_now, p.pending
      FROM basalt_meta.reverts r
      -- Inline, not _revert_progress: a view runs functions as its caller.
      LEFT JOIN LATERAL (SELECT count(l.line_no) FILTER (WHERE l.outcome = 'RESTORED')::int AS restored,
                                count(l.line_no) FILTER (WHERE l.outcome = 'SKIPPED')::int AS skipped,
                                count(l.line_no) FILTER (WHERE l.outcome = 'PENDING')::int AS pending
                           FROM basalt_meta.revert_lines l WHERE l.revert_id = r.revert_id) p ON r.batched
     WHERE r.requested_by = session_user;

-- The lines of the batched plans the calling role prepared.
CREATE VIEW basalt_meta.agent_revert_lines WITH (security_barrier = true) AS
    SELECT l.revert_id, l.line_no, l.line, l.outcome, l.conflict, l.sql_state, l.batch
      FROM basalt_meta.revert_lines l
      JOIN basalt_meta.reverts r ON r.revert_id = l.revert_id
     WHERE r.requested_by = session_user;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA basalt_meta FROM PUBLIC;
GRANT SELECT ON basalt_meta.agent_revert_lines TO {{agents}};
GRANT EXECUTE ON FUNCTION basalt_meta.apply_revert_batch(uuid, int[]) TO {{agents}};
