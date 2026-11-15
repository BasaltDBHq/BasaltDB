-- The guard triggers: guard_row, guard_truncate, the row policy and the
-- commit check.

-- Default policy (fixed until custom policies): up to 10 rows allowed,
-- 11 to 50 held, over 50 refused, every DELETE held. Rows are counted per
-- action, cascades included. M1 has no approvals: held means refused with
-- APPROVAL_REQUIRED until M2.
CREATE FUNCTION basalt_meta._check_policy(c basalt_meta.changes) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog AS $$
DECLARE
    c_allow_max constant int := 10;
    c_hold_max  constant int := 50;
BEGIN
    IF c.rows > c_hold_max THEN
        RAISE EXCEPTION USING ERRCODE = 'BS003', MESSAGE = 'ROW_LIMIT_EXCEEDED',
            DETAIL = format('more than %s rows in one action (cascades included)', c_hold_max);
    END IF;
    IF c.mode = 'APPLY' AND c.approval_id IS NULL AND (c.has_delete OR c.rows > c_allow_max) THEN
        RAISE EXCEPTION USING ERRCODE = 'BS002', MESSAGE = 'APPROVAL_REQUIRED',
            DETAIL = format('%s rows, delete=%s', c.rows, c.has_delete);
    END IF;
END $$;

-- Per-row work for agent writes. SECURITY DEFINER: writes basalt_meta.
CREATE FUNCTION basalt_meta._guard_agent_row(
    p_table regclass, p_op text, p_depth int, p_old jsonb, p_new jsonb, p_old_xmin xid
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_intent   text := nullif(current_setting('basalt.intent', true), '');
    v_mode     text := coalesce(nullif(current_setting('basalt.mode', true), ''), 'APPLY');
    v_approval text := nullif(current_setting('basalt.approval_id', true), '');
    v_run      uuid;
    v_task     uuid;
    v_key      jsonb;
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

    SELECT jsonb_object_agg(k, coalesce(p_old, p_new) -> k) INTO v_key
      FROM basalt_meta.guarded_tables g CROSS JOIN LATERAL unnest(g.pk_cols) k
     WHERE g.table_oid = p_table;

    -- One change per top-level statement in a transaction. Cascaded rows
    -- share the statement timestamp, so they count towards the action that
    -- caused them; their AFTER ROW events fire after every row of the
    -- agent's own statement, so the first row names the action's table and
    -- op, and a row on another table is a cascaded row.
    INSERT INTO basalt_meta.changes AS x (tx, stmt_ts, agent, run_id, task_id, intent, op, table_name,
                                          rows, has_delete, mode, status)
    VALUES (pg_current_xact_id(), statement_timestamp(), session_user, v_run, v_task, v_intent, p_op,
            p_table::text, 1, p_op = 'DELETE', v_mode, CASE v_mode WHEN 'PREVIEW' THEN 'PREVIEW' ELSE 'APPLIED' END)
    ON CONFLICT (tx, stmt_ts) DO UPDATE
       SET rows = x.rows + 1,
           cascaded_rows = x.cascaded_rows + (x.table_name <> excluded.table_name)::int,
           has_delete = x.has_delete OR excluded.has_delete
    RETURNING * INTO c;

    -- Enforced as the count crosses a limit, so a 10 000-row statement
    -- fails at row 11 (or row 1 for a DELETE) instead of after all rows.
    PERFORM basalt_meta._check_policy(c);

    PERFORM basalt_meta._append(session_user, c.change_id, 'ROW_CHANGE', p_table, p_op,
        v_key, p_old, p_new, p_depth,
        jsonb_build_object('xmin', p_old_xmin::text, 'cascaded', c.table_name <> p_table::text));
END $$;

-- The trigger function. People and the app never reach it: the trigger's
-- WHEN clause filters on pg_has_role first. Superusers are members of every
-- role, so they pass WHEN and return here unguarded.
CREATE FUNCTION basalt_meta.guard_row() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF (SELECT r.rolsuper FROM pg_roles r WHERE r.rolname = session_user) THEN
        RETURN NULL;
    END IF;
    PERFORM basalt_meta._guard_agent_row(
        TG_RELID::regclass, TG_OP, pg_trigger_depth(),
        CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END,
        CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END,
        CASE WHEN TG_OP <> 'INSERT' THEN OLD.xmin END);
    RETURN NULL;
END $$;

CREATE FUNCTION basalt_meta.guard_truncate() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF (SELECT r.rolsuper FROM pg_roles r WHERE r.rolname = session_user) THEN
        RETURN NULL;
    END IF;
    RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED', DETAIL = 'TRUNCATE by an agent';
END $$;

-- Deferred to commit: a preview never commits, and the policy is checked
-- again over the whole action. SET CONSTRAINTS ... IMMEDIATE only moves the
-- check earlier, where it sees a partial action and fails closed.
CREATE FUNCTION basalt_meta._at_commit() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    c basalt_meta.changes;
BEGIN
    SELECT * INTO c FROM basalt_meta.changes WHERE change_id = NEW.change_id;
    IF NOT FOUND OR c.status = 'REFUSED' THEN
        RETURN NULL;
    END IF;
    IF c.mode = 'PREVIEW' THEN
        RAISE EXCEPTION USING ERRCODE = 'BS006', MESSAGE = 'PREVIEW_CANNOT_COMMIT';
    END IF;
    PERFORM basalt_meta._check_policy(c);
    RETURN NULL;
END $$;

CREATE CONSTRAINT TRIGGER at_commit AFTER INSERT OR UPDATE ON basalt_meta.changes
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION basalt_meta._at_commit();
