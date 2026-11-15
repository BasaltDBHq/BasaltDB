-- The agent's session functions: start_run, finish_change, record_refusal,
-- record_event and their input checks.

-- Callers of the agent functions must be agent roles, never superusers
-- (superusers are members of every role).
CREATE FUNCTION basalt_meta._require_agent() RETURNS void
LANGUAGE plpgsql STABLE SET search_path = pg_catalog AS $$
BEGIN
    IF NOT pg_has_role(session_user, '{{agents}}', 'MEMBER')
       OR (SELECT r.rolsuper FROM pg_roles r WHERE r.rolname = session_user) THEN
        RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED',
            DETAIL = format('%s is not an agent role', session_user);
    END IF;
END $$;

CREATE FUNCTION basalt_meta._invalid(p_detail text) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'BS008', MESSAGE = 'LEDGER_INPUT_INVALID', DETAIL = p_detail;
END $$;

-- Text inputs: intents up to 2000 bytes, statements and JSON up to 64 KiB.
CREATE FUNCTION basalt_meta._check_text(p_name text, p_value text, p_max int, p_required boolean) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog AS $$
BEGIN
    IF p_required AND coalesce(p_value, '') = '' THEN
        PERFORM basalt_meta._invalid(format('%s is required', p_name));
    END IF;
    IF octet_length(coalesce(p_value, '')) > p_max THEN
        PERFORM basalt_meta._invalid(format('%s is longer than %s bytes', p_name, p_max));
    END IF;
END $$;

-- A uuid session variable, or NULL when unset.
CREATE FUNCTION basalt_meta._setting_uuid(p_name text) RETURNS uuid
LANGUAGE plpgsql STABLE SET search_path = pg_catalog AS $$
DECLARE
    v text := nullif(current_setting(p_name, true), '');
BEGIN
    IF v IS NULL THEN
        RETURN NULL;
    END IF;
    IF v !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
        PERFORM basalt_meta._invalid(format('%s must be a uuid', p_name));
    END IF;
    RETURN v::uuid;
END $$;

-- The run an agent names must be its own; its task id wins over the
-- argument so one run cannot claim another task.
CREATE FUNCTION basalt_meta._run_task(p_run uuid, p_task uuid) RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_task uuid;
BEGIN
    IF p_run IS NULL THEN
        RETURN p_task;
    END IF;
    SELECT r.task_id INTO v_task FROM basalt_meta.runs r WHERE r.run_id = p_run AND r.agent = session_user;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED',
            DETAIL = format('run %s is not a run of %s', p_run, session_user);
    END IF;
    RETURN coalesce(v_task, p_task);
END $$;

CREATE FUNCTION basalt_meta.start_run(p_run_id uuid, p_task_id uuid, p_intent text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    PERFORM basalt_meta._require_agent();
    IF p_run_id IS NULL THEN
        PERFORM basalt_meta._invalid('run id is required');
    END IF;
    PERFORM basalt_meta._check_text('intent', p_intent, 2000, true);
    INSERT INTO basalt_meta.runs (run_id, task_id, agent, intent) VALUES (p_run_id, p_task_id, session_user, p_intent)
    ON CONFLICT (run_id) DO NOTHING;
    IF NOT FOUND THEN
        PERFORM basalt_meta._invalid(format('run %s already exists', p_run_id));
    END IF;
    PERFORM basalt_meta._append(session_user, NULL, 'RUN_STARTED', NULL, NULL, NULL, NULL, NULL, NULL,
        jsonb_build_object('runId', p_run_id, 'taskId', p_task_id, 'intent', p_intent));
END $$;

-- Called by the engine after the agent's statement, before COMMIT. Stamps
-- the change the guard opened in this transaction, or records a zero-row
-- change, and chains a CHANGE row carrying the statement and intent.
CREATE FUNCTION basalt_meta.finish_change(p_op text, p_statement text, p_params jsonb, p_duration_ms int)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_intent text := nullif(current_setting('basalt.intent', true), '');
    v_run    uuid := basalt_meta._setting_uuid('basalt.run_id');
    v_task   uuid;
    c        basalt_meta.changes;
BEGIN
    PERFORM basalt_meta._require_agent();
    PERFORM basalt_meta._check_text('statement', p_statement, 65536, true);
    PERFORM basalt_meta._check_text('params', p_params::text, 65536, false);
    IF p_params IS NOT NULL AND jsonb_typeof(p_params) <> 'array' THEN
        PERFORM basalt_meta._invalid('params must be a JSON array');
    END IF;
    IF p_duration_ms IS NULL OR p_duration_ms < 0 THEN
        PERFORM basalt_meta._invalid('duration must be zero or more');
    END IF;
    IF v_intent IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'BS001', MESSAGE = 'INTENT_REQUIRED',
            DETAIL = format('finish_change by %s without basalt.intent', session_user);
    END IF;
    v_task := basalt_meta._run_task(v_run, basalt_meta._setting_uuid('basalt.task_id'));

    SELECT * INTO c FROM basalt_meta.changes x
     WHERE x.tx = pg_current_xact_id_if_assigned() AND x.agent = session_user AND x.statement IS NULL
     ORDER BY x.stmt_ts DESC LIMIT 1;
    IF FOUND THEN
        UPDATE basalt_meta.changes x SET statement = p_statement, params = p_params, duration_ms = p_duration_ms
         WHERE x.change_id = c.change_id
        RETURNING * INTO c;
    ELSE
        IF p_op IS NULL OR p_op NOT IN ('INSERT', 'UPDATE', 'DELETE') THEN
            PERFORM basalt_meta._invalid('op must be INSERT, UPDATE or DELETE');
        END IF;
        INSERT INTO basalt_meta.changes (tx, stmt_ts, agent, run_id, task_id, intent, op, statement, params,
                                         duration_ms, mode, status)
        VALUES (pg_current_xact_id(), statement_timestamp(), session_user, v_run, v_task, v_intent, p_op,
                p_statement, p_params, p_duration_ms,
                coalesce(nullif(current_setting('basalt.mode', true), ''), 'APPLY'),
                CASE WHEN current_setting('basalt.mode', true) = 'PREVIEW' THEN 'PREVIEW' ELSE 'APPLIED' END)
        RETURNING * INTO c;
    END IF;
    PERFORM basalt_meta._append(session_user, c.change_id, 'CHANGE', NULL, c.op, NULL, NULL, NULL, NULL,
        jsonb_build_object('runId', c.run_id, 'taskId', c.task_id, 'intent', c.intent, 'statement', c.statement,
                           'table', c.table_name, 'rows', c.rows, 'cascadedRows', c.cascaded_rows,
                           'durationMs', c.duration_ms, 'status', c.status));
    RETURN c.change_id;
END $$;

-- A refused action: the engine refused it, or the guard raised and the
-- transaction rolled back. Written in a new transaction.
CREATE FUNCTION basalt_meta.record_refusal(
    p_run_id uuid, p_task_id uuid, p_intent text, p_op text, p_statement text, p_params jsonb,
    p_code text, p_reason text, p_duration_ms int
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_task uuid;
    v_id   uuid;
BEGIN
    PERFORM basalt_meta._require_agent();
    PERFORM basalt_meta._check_text('intent', p_intent, 2000, false);
    PERFORM basalt_meta._check_text('statement', p_statement, 65536, false);
    PERFORM basalt_meta._check_text('params', p_params::text, 65536, false);
    PERFORM basalt_meta._check_text('reason', p_reason, 2000, false);
    IF p_op IS NULL OR p_op NOT IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'OTHER') THEN
        PERFORM basalt_meta._invalid('op must be SELECT, INSERT, UPDATE, DELETE or OTHER');
    END IF;
    IF p_code IS NULL OR p_code !~ '^[A-Z][A-Z_]{0,63}$' THEN
        PERFORM basalt_meta._invalid('code must be SCREAMING_SNAKE_CASE');
    END IF;
    IF p_duration_ms IS NOT NULL AND p_duration_ms < 0 THEN
        PERFORM basalt_meta._invalid('duration must be zero or more');
    END IF;
    v_task := basalt_meta._run_task(p_run_id, p_task_id);
    INSERT INTO basalt_meta.changes (tx, stmt_ts, agent, run_id, task_id, intent, op, statement, params,
                                     duration_ms, status, code, reason)
    VALUES (pg_current_xact_id(), statement_timestamp(), session_user, p_run_id, v_task, nullif(p_intent, ''),
            p_op, p_statement, p_params, p_duration_ms, 'REFUSED', p_code, p_reason)
    RETURNING change_id INTO v_id;
    PERFORM basalt_meta._append(session_user, v_id, 'REFUSED', NULL, p_op, NULL, NULL, NULL, NULL,
        jsonb_build_object('runId', p_run_id, 'taskId', v_task, 'intent', p_intent, 'statement', p_statement,
                           'code', p_code, 'reason', p_reason));
    RETURN v_id;
END $$;

-- Engine events. M1 accepts HEARTBEAT (dead-man switch, D14).
CREATE FUNCTION basalt_meta.record_event(p_kind text, p_run_id uuid, p_detail jsonb) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    PERFORM basalt_meta._require_agent();
    IF p_kind IS NULL OR p_kind NOT IN ('HEARTBEAT') THEN
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
