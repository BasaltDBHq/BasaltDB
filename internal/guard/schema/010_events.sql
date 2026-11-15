-- record_event with the engine events.

-- Engine events: HEARTBEAT every hour, DEAD_MAN when the engine checks in
-- after more than 7 days of silence (D14), UNCOVERED_TABLES when the set
-- of unguarded tables changes.
CREATE OR REPLACE FUNCTION basalt_meta.record_event(p_kind text, p_run_id uuid, p_detail jsonb) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    PERFORM basalt_meta._require_agent();
    IF p_kind IS NULL OR p_kind NOT IN ('HEARTBEAT', 'DEAD_MAN', 'UNCOVERED_TABLES') THEN
        PERFORM basalt_meta._invalid(format('kind %s', p_kind));
    END IF;
    IF p_detail IS NULL OR jsonb_typeof(p_detail) <> 'object' THEN
        PERFORM basalt_meta._invalid('detail must be a JSON object');
    END IF;
    PERFORM basalt_meta._check_text('detail', p_detail::text, 65536, true);
    PERFORM basalt_meta._run_task(p_run_id, NULL);
    RETURN basalt_meta._append(session_user, NULL, p_kind, NULL, NULL, NULL, NULL, NULL, NULL,
        p_detail || jsonb_build_object('runId', p_run_id));
END $$;
