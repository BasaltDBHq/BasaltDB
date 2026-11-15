-- The row trigger with recorded reads: the stale-read check and row
-- versions.

-- The row trigger's work, now with the stale-read check (BS004) and the
-- version of the new row, so the run's own writes move its known version.
DROP FUNCTION basalt_meta._guard_agent_row(regclass, text, int, jsonb, jsonb, xid);

-- The primary key of a row image, as the ledger and reads key it.
CREATE FUNCTION basalt_meta._row_key(p_table regclass, p_row jsonb) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT jsonb_object_agg(k, p_row -> k)
      FROM basalt_meta.guarded_tables g CROSS JOIN LATERAL unnest(g.pk_cols) k
     WHERE g.table_oid = p_table
$$;

CREATE FUNCTION basalt_meta._guard_agent_row(
    p_table regclass, p_op text, p_depth int, p_old jsonb, p_new jsonb, p_old_xmin xid, p_new_xmin xid
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_intent   text := nullif(current_setting('basalt.intent', true), '');
    v_mode     text := coalesce(nullif(current_setting('basalt.mode', true), ''), 'APPLY');
    v_approval text := nullif(current_setting('basalt.approval_id', true), '');
    v_run      uuid;
    v_task     uuid;
    v_key      jsonb;
    v_read     basalt_meta.reads;
    v_detail   jsonb;
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
    IF v_approval IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'APPROVAL_INVALID',
            DETAIL = 'approvals are not available until M2';
    END IF;
    v_run := basalt_meta._setting_uuid('basalt.run_id');
    v_task := basalt_meta._run_task(v_run, basalt_meta._setting_uuid('basalt.task_id'));
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
                                          rows, has_delete, mode, status)
    VALUES (pg_current_xact_id(), statement_timestamp(), session_user, v_run, v_task, v_intent, p_op,
            p_table::text, 1, p_op = 'DELETE', v_mode, CASE v_mode WHEN 'PREVIEW' THEN 'PREVIEW' ELSE 'APPLIED' END)
    ON CONFLICT (tx, stmt_ts) DO UPDATE
       SET rows = x.rows + 1,
           cascaded_rows = x.cascaded_rows + (x.table_name <> excluded.table_name)::int,
           has_delete = x.has_delete OR excluded.has_delete
    RETURNING * INTO c;
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

CREATE OR REPLACE FUNCTION basalt_meta.guard_row() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF (SELECT r.rolsuper FROM pg_roles r WHERE r.rolname = session_user) THEN
        RETURN NULL;
    END IF;
    PERFORM basalt_meta._guard_agent_row(
        TG_RELID::regclass, TG_OP, pg_trigger_depth(),
        CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END,
        CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END,
        CASE WHEN TG_OP <> 'INSERT' THEN OLD.xmin END,
        CASE WHEN TG_OP <> 'DELETE' THEN NEW.xmin END);
    RETURN NULL;
END $$;

-- Reads are change records too; the write policy does not apply to them.
CREATE OR REPLACE FUNCTION basalt_meta._at_commit() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    c basalt_meta.changes;
BEGIN
    SELECT * INTO c FROM basalt_meta.changes WHERE change_id = NEW.change_id;
    IF NOT FOUND OR c.status = 'REFUSED' OR c.op = 'SELECT' THEN
        RETURN NULL;
    END IF;
    IF c.mode = 'PREVIEW' THEN
        RAISE EXCEPTION USING ERRCODE = 'BS006', MESSAGE = 'PREVIEW_CANNOT_COMMIT';
    END IF;
    PERFORM basalt_meta._check_policy(c);
    RETURN NULL;
END $$;

GRANT SELECT ON basalt_meta.agent_guarded_tables TO {{agents}};
GRANT EXECUTE ON FUNCTION basalt_meta.record_read(uuid, text, jsonb, text[], int, int, jsonb) TO {{agents}};
