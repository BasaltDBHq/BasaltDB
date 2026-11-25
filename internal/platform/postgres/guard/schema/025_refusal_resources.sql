-- Version 12: a refusal names its resources. record_refusal takes the
-- resources the refused statement names, qualified by the engine in the
-- agent's own session (CONTRACT.md, basalt_meta), and records the first on
-- the change record and all of them in the REFUSED ledger row's detail, as
-- record_read does for a read. A refusal is always recorded: names it cannot
-- keep are left out, never raised on. The nine-argument form is dropped: the
-- engine of this version calls the new one only.

DROP FUNCTION IF EXISTS basalt_meta.record_refusal(uuid, uuid, text, text, text, jsonb, text, text, int);

-- A refused action: the engine refused it, or the guard raised and the
-- transaction rolled back. Written in a new transaction. p_resources are
-- the resources the statement names, a write's target first, empty or NULL
-- when it did not parse. The first 100 that are neither empty nor over 1000
-- bytes are kept, in order; the rest are left out, so no name can keep the
-- refusal out of the ledger.
CREATE OR REPLACE FUNCTION basalt_meta.record_refusal(
    p_run_id uuid, p_task_id uuid, p_intent text, p_op text, p_statement text, p_params jsonb,
    p_code text, p_reason text, p_duration_ms int, p_resources text[]
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_max_resources constant int := 100;
    v_task      uuid;
    v_id        uuid;
    v_resources text[];
BEGIN
    PERFORM basalt_meta._require_agent();
    PERFORM basalt_meta._check_text('intent', p_intent, 2000, false);
    PERFORM basalt_meta._check_text('statement', p_statement, 65536, false);
    PERFORM basalt_meta._check_text('params', p_params::text, 65536, false);
    PERFORM basalt_meta._check_text('reason', p_reason, 2000, false);
    IF p_op IS NULL OR p_op NOT IN ('READ', 'INSERT', 'UPDATE', 'DELETE', 'OTHER') THEN
        PERFORM basalt_meta._invalid('op must be READ, INSERT, UPDATE, DELETE or OTHER');
    END IF;
    IF p_code IS NULL OR p_code !~ '^[A-Z][A-Z_]{0,63}$' THEN
        PERFORM basalt_meta._invalid('code must be SCREAMING_SNAKE_CASE');
    END IF;
    IF p_duration_ms IS NOT NULL AND p_duration_ms < 0 THEN
        PERFORM basalt_meta._invalid('duration must be zero or more');
    END IF;
    v_resources := ARRAY(SELECT u.t FROM unnest(p_resources) WITH ORDINALITY AS u(t, i)
                          WHERE coalesce(u.t, '') <> '' AND octet_length(u.t) <= 1000
                          ORDER BY u.i LIMIT c_max_resources);
    v_task := basalt_meta._run_task(p_run_id, p_task_id);
    INSERT INTO basalt_meta.changes (tx, stmt_ts, agent, run_id, task_id, intent, op, table_name, statement, params,
                                     duration_ms, status, code, reason)
    VALUES (pg_current_xact_id(), statement_timestamp(), session_user, p_run_id, v_task, nullif(p_intent, ''),
            p_op, v_resources[1], p_statement, p_params, p_duration_ms, 'REFUSED', p_code, p_reason)
    RETURNING change_id INTO v_id;
    PERFORM basalt_meta._append(session_user, v_id, 'REFUSED', NULL, p_op, NULL, NULL, NULL, NULL,
        jsonb_build_object('runId', p_run_id, 'taskId', v_task, 'intent', p_intent, 'statement', p_statement,
                           'resources', to_jsonb(v_resources),
                           'code', p_code, 'reason', p_reason));
    RETURN v_id;
END $$;

REVOKE ALL ON FUNCTION basalt_meta.record_refusal(uuid, uuid, text, text, text, jsonb, text, text, int, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION basalt_meta.record_refusal(uuid, uuid, text, text, text, jsonb, text, text, int, text[]) TO {{agents}};
