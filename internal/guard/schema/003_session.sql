-- An agent's session: runs, change records, refusals and engine events,
-- and recorded reads with the stale-read check. Every function here runs in
-- the agent's own transaction and checks its caller is an agent role.

-- Callers of the agent functions must be agent roles (members of the agents
-- group with USAGE, that is inheriting it), never superusers (superusers
-- are members of every role).
CREATE OR REPLACE FUNCTION basalt_meta._require_agent() RETURNS void
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT pg_has_role(session_user, '{{agents}}', 'USAGE')
       OR (SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = session_user) THEN
        RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED',
            DETAIL = format('%s is not an agent role', session_user);
    END IF;
END $$;

CREATE FUNCTION basalt_meta._invalid(p_detail text) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'BS008', MESSAGE = 'LEDGER_INPUT_INVALID', DETAIL = p_detail;
END $$;

-- Text inputs: intents up to 2000 bytes, statements and JSON up to 64 KiB.
CREATE FUNCTION basalt_meta._check_text(p_name text, p_value text, p_max int, p_required boolean) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
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
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
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
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
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
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
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
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
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
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
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

-- Engine events: HEARTBEAT every hour, DEAD_MAN when the engine checks in
-- after more than 7 days of silence (D14), UNCOVERED_TABLES when the set
-- of unguarded tables changes.
CREATE OR REPLACE FUNCTION basalt_meta.record_event(p_kind text, p_run_id uuid, p_detail jsonb) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
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

-- One version entry of record_read: an object naming a guarded table the
-- caller can read, a key with exactly its primary-key columns, and an xid.
CREATE FUNCTION basalt_meta._check_version(p_v jsonb) RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_u32_max constant bigint := 4294967295; -- oid and xid are unsigned 32-bit
    v_pk      text[];
BEGIN
    IF jsonb_typeof(p_v) IS DISTINCT FROM 'object'
       OR coalesce(p_v ->> 'tableOid', '') !~ '^[0-9]{1,10}$'
       OR coalesce(p_v ->> 'version', '') !~ '^[0-9]{1,10}$'
       OR jsonb_typeof(p_v -> 'key') IS DISTINCT FROM 'object' THEN
        PERFORM basalt_meta._invalid('each version needs tableOid, key (an object) and version (an xid)');
    END IF;
    IF (p_v ->> 'tableOid')::bigint > c_u32_max OR (p_v ->> 'version')::bigint > c_u32_max THEN
        PERFORM basalt_meta._invalid('tableOid and version must fit 32 bits');
    END IF;
    SELECT g.pk_cols INTO v_pk FROM basalt_meta.guarded_tables g WHERE g.table_oid = (p_v ->> 'tableOid')::oid;
    IF NOT FOUND OR NOT coalesce(has_table_privilege(session_user, (p_v ->> 'tableOid')::oid, 'SELECT'), false) THEN
        PERFORM basalt_meta._invalid(format('table %s is not a guarded table %s can read', p_v ->> 'tableOid', session_user));
    END IF;
    IF (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(p_v -> 'key') k)
       IS DISTINCT FROM (SELECT array_agg(k ORDER BY k) FROM unnest(v_pk) k) THEN
        PERFORM basalt_meta._invalid(format('key must name exactly the primary-key columns %s', v_pk));
    END IF;
END $$;

-- One read the engine ran: a SELECT change record, a READ ledger row with
-- the versions it saw, and for a run the run's known version of each row.
-- Called in its own transaction after the read-only one.
CREATE FUNCTION basalt_meta.record_read(
    p_run_id uuid, p_statement text, p_params jsonb, p_tables text[], p_row_count int, p_duration_ms int,
    p_versions jsonb
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_max_versions constant int := 10000;
    c_max_tables   constant int := 100;
    v_versions jsonb := coalesce(p_versions, '[]'::jsonb);
    v_task     uuid;
    v_intent   text;
    v_id       uuid;
    v_seen     jsonb;
    e          jsonb;
BEGIN
    PERFORM basalt_meta._require_agent();
    PERFORM basalt_meta._check_text('statement', p_statement, 65536, true);
    PERFORM basalt_meta._check_text('params', p_params::text, 65536, false);
    IF p_params IS NOT NULL AND jsonb_typeof(p_params) <> 'array' THEN
        PERFORM basalt_meta._invalid('params must be a JSON array');
    END IF;
    IF p_row_count IS NULL OR p_row_count < 0 OR (p_duration_ms IS NOT NULL AND p_duration_ms < 0) THEN
        PERFORM basalt_meta._invalid('row count and duration must be zero or more');
    END IF;
    IF coalesce(cardinality(p_tables), 0) > c_max_tables
       OR EXISTS (SELECT 1 FROM unnest(p_tables) t WHERE coalesce(t, '') = '' OR octet_length(t) > 1000) THEN
        PERFORM basalt_meta._invalid(format('tables: at most %s names', c_max_tables));
    END IF;
    IF jsonb_typeof(v_versions) <> 'array' OR jsonb_array_length(v_versions) > c_max_versions THEN
        PERFORM basalt_meta._invalid(format('versions must be a JSON array of at most %s entries', c_max_versions));
    END IF;
    FOR e IN SELECT x FROM jsonb_array_elements(v_versions) x LOOP
        PERFORM basalt_meta._check_version(e);
    END LOOP;
    v_task := basalt_meta._run_task(p_run_id, NULL);
    SELECT r.intent INTO v_intent FROM basalt_meta.runs r WHERE r.run_id = p_run_id;

    INSERT INTO basalt_meta.changes (tx, stmt_ts, agent, run_id, task_id, intent, op, table_name, statement, params,
                                     rows, duration_ms, status)
    VALUES (pg_current_xact_id(), statement_timestamp(), session_user, p_run_id, v_task, v_intent, 'SELECT',
            p_tables[1], p_statement, p_params, p_row_count, p_duration_ms, 'APPLIED')
    RETURNING change_id INTO v_id;

    IF p_run_id IS NOT NULL THEN
        -- DISTINCT ON: a self-join returns the same row twice.
        INSERT INTO basalt_meta.reads AS r (run_id, table_oid, row_key, row_version, change_id)
        SELECT DISTINCT ON ((x ->> 'tableOid')::oid, x -> 'key')
               p_run_id, (x ->> 'tableOid')::oid, x -> 'key', (x ->> 'version')::xid, v_id
          FROM jsonb_array_elements(v_versions) x
        ON CONFLICT (run_id, table_oid, row_key) DO UPDATE
           SET row_version = excluded.row_version, change_id = excluded.change_id, at = excluded.at;
    END IF;

    SELECT coalesce(jsonb_agg(jsonb_build_object(
               'table', (x ->> 'tableOid')::oid::regclass::text, 'key', x -> 'key',
               'version', 'xmin:' || (x ->> 'version')) ORDER BY n), '[]'::jsonb)
      INTO v_seen
      FROM jsonb_array_elements(v_versions) WITH ORDINALITY v(x, n);
    PERFORM basalt_meta._append(session_user, v_id, 'READ', NULL, 'SELECT', NULL, NULL, NULL, NULL,
        jsonb_build_object('runId', p_run_id, 'taskId', v_task, 'statement', p_statement,
                           'tables', to_jsonb(coalesce(p_tables, '{}'::text[])), 'rows', p_row_count,
                           'durationMs', p_duration_ms, 'versions', v_seen));
    RETURN v_id;
END $$;

-- The primary key of a row image, as the ledger and reads key it.
CREATE FUNCTION basalt_meta._row_key(p_table regclass, p_row jsonb) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT jsonb_object_agg(k, p_row -> k)
      FROM basalt_meta.guarded_tables g CROSS JOIN LATERAL unnest(g.pk_cols) k
     WHERE g.table_oid = p_table
$$;

-- The row trigger's work for an agent write: the stale-read check (BS004)
-- and the version of the new row, so the run's own writes move its known
-- version. basalt.approval_id names a signed approval of this agent and
-- run, the action may not exceed its rows, and the change carries the
-- approval id so the policy lets it through and the commit check compares
-- it.
CREATE OR REPLACE FUNCTION basalt_meta._guard_agent_row(
    p_table regclass, p_op text, p_depth int, p_old jsonb, p_new jsonb, p_old_xmin xid, p_new_xmin xid
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_intent   text := nullif(current_setting('basalt.intent', true), '');
    v_mode     text := coalesce(nullif(current_setting('basalt.mode', true), ''), 'APPLY');
    v_approval uuid;
    v_run      uuid;
    v_task     uuid;
    v_key      jsonb;
    v_read     basalt_meta.reads;
    v_detail   jsonb;
    a          basalt_meta.approvals;
    c          basalt_meta.changes;
BEGIN
    IF v_intent IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'BS001', MESSAGE = 'INTENT_REQUIRED',
            DETAIL = format('%s on %s by %s without basalt.intent', p_op, p_table, session_user);
    END IF;
    PERFORM basalt_meta._check_text('basalt.intent', v_intent, 2000, true);
    IF v_mode NOT IN ('APPLY', 'PREVIEW') THEN
        RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED', DETAIL = format('unknown basalt.mode %s', v_mode);
    END IF;
    v_run := basalt_meta._setting_uuid('basalt.run_id');
    v_task := basalt_meta._run_task(v_run, basalt_meta._setting_uuid('basalt.task_id'));
    v_approval := basalt_meta._setting_uuid('basalt.approval_id');
    IF v_approval IS NOT NULL THEN
        IF v_mode <> 'APPLY' THEN
            RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED', DETAIL = 'a preview cannot use an approval';
        END IF;
        a := basalt_meta._check_approval(v_approval, v_run);
    END IF;
    v_key := basalt_meta._row_key(p_table, coalesce(p_old, p_new));

    -- STALE_READ: the row changed since this run last read or wrote it.
    -- Checked before the policy, so a stale DELETE says STALE_READ.
    IF v_run IS NOT NULL AND p_op <> 'INSERT' THEN
        SELECT * INTO v_read FROM basalt_meta.reads r
         WHERE r.run_id = v_run AND r.table_oid = p_table AND r.row_key = v_key;
        IF FOUND AND NOT (v_read.row_version = p_old_xmin) THEN
            RAISE EXCEPTION USING ERRCODE = 'BS004', MESSAGE = 'STALE_READ',
                DETAIL = format('%s %s read at xmin %s, now %s', p_table, v_key, v_read.row_version, p_old_xmin),
                HINT = 'read the row again in this run, then decide';
        END IF;
    END IF;

    -- One change per top-level statement in a transaction (see version 1).
    INSERT INTO basalt_meta.changes AS x (tx, stmt_ts, agent, run_id, task_id, intent, op, table_name,
                                          rows, has_delete, mode, approval_id, status)
    VALUES (pg_current_xact_id(), statement_timestamp(), session_user, v_run, v_task, v_intent, p_op,
            p_table::text, 1, p_op = 'DELETE', v_mode, v_approval,
            CASE v_mode WHEN 'PREVIEW' THEN 'PREVIEW' ELSE 'APPLIED' END)
    ON CONFLICT (tx, stmt_ts) DO UPDATE
       SET rows = x.rows + 1,
           cascaded_rows = x.cascaded_rows + (x.table_name <> excluded.table_name)::int,
           has_delete = x.has_delete OR excluded.has_delete
    RETURNING * INTO c;
    IF v_approval IS NOT NULL AND c.rows > a.rows THEN
        PERFORM basalt_meta._approval_invalid(format('the action changes more than the %s rows approved', a.rows));
    END IF;
    PERFORM basalt_meta._check_policy(c);

    -- newXmin: the version this write leaves (the writing transaction id),
    -- NULL for a DELETE; revert (M3) compares it with the row's xmin.
    v_detail := jsonb_build_object('xmin', p_old_xmin::text, 'newXmin', p_new_xmin::text,
                                   'cascaded', c.table_name <> p_table::text);
    IF v_read.run_id IS NOT NULL THEN
        v_detail := v_detail || jsonb_build_object('basedOn',
            jsonb_build_object('version', 'xmin:' || p_old_xmin::text, 'changeId', v_read.change_id));
    ELSIF p_op <> 'INSERT' AND c.table_name = p_table::text THEN
        v_detail := v_detail || jsonb_build_object('blindWrite', true); -- D15: allowed, marked
    END IF;
    PERFORM basalt_meta._append(session_user, c.change_id, 'ROW_CHANGE', p_table, p_op,
        v_key, p_old, p_new, p_depth, v_detail);

    -- Cascaded rows are not tracked: the run did not pick them, and a row of
    -- a table the agent cannot read must never reach a STALE_READ message.
    IF v_run IS NULL OR c.table_name <> p_table::text THEN
        RETURN;
    END IF;
    -- The run knows the row as it just wrote it (or knows it is gone).
    DELETE FROM basalt_meta.reads r WHERE r.run_id = v_run AND r.table_oid = p_table AND r.row_key = v_key;
    IF p_op <> 'DELETE' THEN
        INSERT INTO basalt_meta.reads AS r (run_id, table_oid, row_key, row_version, change_id)
        VALUES (v_run, p_table, basalt_meta._row_key(p_table, p_new), p_new_xmin, c.change_id)
        ON CONFLICT (run_id, table_oid, row_key) DO UPDATE
           SET row_version = excluded.row_version, change_id = excluded.change_id, at = excluded.at;
    END IF;
END $$;
