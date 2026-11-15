-- Retention: _prune and prune.

-- Retention (D10): old and new values (ledger rows, change params) are
-- kept 30 days; other ledger metadata 1 year. Values are nulled, not
-- deleted, and the chain hashes their digest, so it stays verifiable. The
-- oldest rows are deleted as a prefix and the anchor moves to the last one.
CREATE FUNCTION basalt_meta._prune(p_now timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    c_values_ttl constant interval := interval '30 days';
    c_meta_ttl   constant interval := interval '1 year';
    v_values bigint := 0;
    v_rows   bigint := 0;
    v_cut    bigint;
BEGIN
    UPDATE basalt_meta.ledger SET old_row = NULL, new_row = NULL, values_pruned = true
     WHERE NOT values_pruned AND at < p_now - c_values_ttl AND (old_row IS NOT NULL OR new_row IS NOT NULL);
    GET DIAGNOSTICS v_values = ROW_COUNT;
    UPDATE basalt_meta.changes SET params = NULL WHERE params IS NOT NULL AND at < p_now - c_values_ttl;

    SELECT max(seq) INTO v_cut FROM basalt_meta.ledger WHERE at < p_now - c_meta_ttl;
    IF v_cut IS NOT NULL THEN
        UPDATE basalt_meta.chain_anchor a SET seq = l.seq, hash = l.hash
          FROM basalt_meta.ledger l WHERE a.id AND l.seq = v_cut;
        DELETE FROM basalt_meta.ledger WHERE seq <= v_cut;
        GET DIAGNOSTICS v_rows = ROW_COUNT;
        DELETE FROM basalt_meta.changes WHERE at < p_now - c_meta_ttl;
        DELETE FROM basalt_meta.runs WHERE started_at < p_now - c_meta_ttl;
    END IF;

    IF v_values + v_rows > 0 THEN
        PERFORM basalt_meta._append(session_user, NULL, 'PRUNED', NULL, NULL, NULL, NULL, NULL, NULL,
            jsonb_build_object('valuesPruned', v_values, 'rowsDeleted', v_rows));
    END IF;
    RETURN jsonb_build_object('valuesPruned', v_values, 'rowsDeleted', v_rows);
END $$;

-- The engine's timer calls this. Agents cannot choose the clock.
CREATE FUNCTION basalt_meta.prune() RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    PERFORM basalt_meta._require_agent();
    RETURN basalt_meta._prune(now());
END $$;
