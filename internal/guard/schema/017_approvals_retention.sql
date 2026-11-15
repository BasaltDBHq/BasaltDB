-- Retention with approvals.

-- Retention (version 1) plus approvals: a held write past its expiry is
-- APPROVAL_EXPIRED; approval values are pruned with other values after 30
-- days and the rows deleted after 1 year.
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

    SELECT max(seq) INTO v_cut FROM basalt_meta.ledger WHERE at < p_now - c_meta_ttl;
    IF v_cut IS NOT NULL THEN
        UPDATE basalt_meta.chain_anchor a SET seq = l.seq, hash = l.hash
          FROM basalt_meta.ledger l WHERE a.id AND l.seq = v_cut;
        DELETE FROM basalt_meta.ledger WHERE seq <= v_cut;
        GET DIAGNOSTICS v_rows = ROW_COUNT;
        DELETE FROM basalt_meta.changes WHERE at < p_now - c_meta_ttl;
        DELETE FROM basalt_meta.runs WHERE started_at < p_now - c_meta_ttl;
        DELETE FROM basalt_meta.approvals WHERE created_at < p_now - c_meta_ttl;
    END IF;

    IF v_values + v_rows > 0 THEN
        PERFORM basalt_meta._append(session_user, NULL, 'PRUNED', NULL, NULL, NULL, NULL, NULL, NULL,
            jsonb_build_object('valuesPruned', v_values, 'rowsDeleted', v_rows));
    END IF;
    RETURN jsonb_build_object('valuesPruned', v_values, 'rowsDeleted', v_rows, 'approvalsExpired', v_expired);
END $$;
