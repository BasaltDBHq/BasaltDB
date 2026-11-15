-- Running revert items in batches: the trial, the revert writes and the
-- revert row trigger.

-- A trial's writes are rolled back, so the guard records nothing for them.
ALTER TABLE basalt_meta.revert_running ADD COLUMN trial boolean NOT NULL DEFAULT false;

-- A row written by a revert (version 6): it must be the one row the revert
-- is writing now, named in basalt.revert_target by _revert_write just
-- before the write (no cascade, no app trigger reaching another row).
-- The target is a transaction-local setting rather than an update of the
-- revert_running row: thousands of updates of one row in one transaction
-- made every lookup walk their versions. Only revert_running, which only
-- the revert functions write, says a revert is running; the setting only
-- narrows which row it may write.
CREATE OR REPLACE FUNCTION basalt_meta._guard_revert_row(
    p_table regclass, p_op text, p_depth int, p_old jsonb, p_new jsonb, p_old_xmin xid, p_new_xmin xid
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    r        basalt_meta.revert_running;
    v_key    jsonb := basalt_meta._row_key(p_table, coalesce(p_old, p_new));
    v_target jsonb := nullif(current_setting('basalt.revert_target', true), '')::jsonb;
BEGIN
    SELECT * INTO r FROM basalt_meta.revert_running x WHERE x.tx = pg_current_xact_id();
    IF p_depth > 1 OR (v_target ->> 'table')::oid IS DISTINCT FROM p_table::oid OR (v_target -> 'key') IS DISTINCT FROM v_key THEN
        RAISE EXCEPTION USING ERRCODE = 'BS009', MESSAGE = 'REVERT_CASCADE',
            DETAIL = format('%s %s %s is not part of the revert', p_op, p_table, v_key);
    END IF;
    IF r.trial THEN
        RETURN;
    END IF;
    PERFORM basalt_meta._append(r.agent, r.change_id, 'ROW_CHANGE', p_table, p_op, v_key, p_old, p_new, p_depth,
        jsonb_build_object('xmin', p_old_xmin::text, 'newXmin', p_new_xmin::text, 'cascaded', false,
                           'revertOf', v_target -> 'revertOf'));
END $$;

-- One inverse write (version 6), naming its row in basalt.revert_target.
CREATE OR REPLACE FUNCTION basalt_meta._revert_write(it basalt_meta.revert_item) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_tbl   text := it.table_oid::regclass::text;
    v_where text;
    v_cols  text;
    v_vals  text;
    v_n     bigint;
BEGIN
    PERFORM set_config('basalt.revert_target',
        jsonb_build_object('table', it.table_oid, 'key', it.key, 'revertOf', to_jsonb(it.change_ids))::text, true);
    SELECT format('(%s) = (SELECT %s FROM jsonb_populate_record(NULL::%s, $2) k)',
                  string_agg(format('t.%I', c), ', ' ORDER BY n), string_agg(format('k.%I', c), ', ' ORDER BY n), v_tbl)
      INTO v_where
      FROM basalt_meta.guarded_tables g CROSS JOIN LATERAL unnest(g.pk_cols) WITH ORDINALITY u(c, n)
     WHERE g.table_oid = it.table_oid::regclass;
    SELECT string_agg(format('%I', k), ', ' ORDER BY k), string_agg(format('r.%I', k), ', ' ORDER BY k)
      INTO v_cols, v_vals
      FROM jsonb_object_keys(coalesce(it.set, '{}'::jsonb)) k
     WHERE it.op = 'INSERT' OR (it.now -> k) IS DISTINCT FROM (it.set -> k);
    IF it.op = 'UPDATE' AND v_cols IS NULL THEN
        RETURN NULL; -- the agent left the values as they were
    END IF;
    BEGIN
        -- Dynamic SQL on a validated table (regclass) and quoted columns.
        CASE it.op
        WHEN 'DELETE' THEN
            EXECUTE format('DELETE FROM %s t WHERE %s', v_tbl, v_where) USING NULL::jsonb, it.key;
        WHEN 'UPDATE' THEN
            EXECUTE format('UPDATE %s t SET (%s) = (SELECT %s FROM jsonb_populate_record(NULL::%s, $1) r) WHERE %s',
                           v_tbl, v_cols, v_vals, v_tbl, v_where) USING it.set, it.key;
        ELSE
            EXECUTE format('INSERT INTO %s (%s) OVERRIDING SYSTEM VALUE SELECT %s FROM jsonb_populate_record(NULL::%s, $1) r',
                           v_tbl, v_cols, v_vals, v_tbl) USING it.set;
        END CASE;
        GET DIAGNOSTICS v_n = ROW_COUNT;
        IF v_n <> 1 THEN
            RAISE EXCEPTION USING ERRCODE = 'BS098', MESSAGE = 'ROW_GONE';
        END IF;
    EXCEPTION WHEN OTHERS THEN
        RETURN SQLSTATE;
    END;
    RETURN NULL;
END $$;

-- Run the RESTORE items (version 6), numbering each write that lands in
-- the order it landed (step).
CREATE OR REPLACE FUNCTION basalt_meta._revert_execute(p_items basalt_meta.revert_item[]) RETURNS basalt_meta.revert_item[]
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_items    basalt_meta.revert_item[] := p_items;
    v_pending  int[];
    v_retry    int[];
    v_progress boolean;
    v_state    text;
    v_phase    text;
    v_step     int := 0;
    i          int;
    it         basalt_meta.revert_item;
BEGIN
    SET CONSTRAINTS ALL IMMEDIATE;
    FOREACH v_phase IN ARRAY ARRAY['DELETE', 'UPDATE', 'INSERT'] LOOP
        v_pending := ARRAY(SELECT n FROM generate_subscripts(v_items, 1) n
                            WHERE (v_items[n]).op = v_phase AND (v_items[n]).conflict IS NULL
                            ORDER BY CASE WHEN v_phase = 'INSERT' THEN (v_items[n]).first_seq ELSE -(v_items[n]).last_seq END);
        LOOP
            v_retry := '{}';
            v_progress := false;
            FOREACH i IN ARRAY v_pending LOOP
                v_state := basalt_meta._revert_write(v_items[i]);
                it := v_items[i];
                CASE
                WHEN v_state IS NULL THEN
                    v_progress := true;
                    v_step := v_step + 1;
                    it.step := v_step;
                WHEN v_state = '23503' THEN
                    v_retry := v_retry || i;
                ELSE
                    it.conflict := CASE v_state WHEN 'BS009' THEN 'CASCADE' WHEN 'BS098' THEN 'ROW_GONE' ELSE 'CONSTRAINT' END;
                    it.sql_state := CASE WHEN it.conflict = 'CONSTRAINT' THEN v_state END;
                END CASE;
                v_items[i] := it;
            END LOOP;
            EXIT WHEN cardinality(v_retry) = 0 OR NOT v_progress;
            v_pending := v_retry;
        END LOOP;
        FOREACH i IN ARRAY v_retry LOOP
            it := v_items[i];
            it.conflict := 'CONSTRAINT';
            it.sql_state := '23503';
            v_items[i] := it;
        END LOOP;
    END LOOP;
    RETURN v_items;
END $$;

-- The items of a trial run that always rolls back: conflicts found on
-- trial and the step of every write that landed.
CREATE FUNCTION basalt_meta._revert_trial_items(p_items basalt_meta.revert_item[]) RETURNS basalt_meta.revert_item[]
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_items basalt_meta.revert_item[];
BEGIN
    BEGIN
        INSERT INTO basalt_meta.revert_running (tx, agent, change_id, trial)
        VALUES (pg_current_xact_id(), session_user, basalt_meta._uuidv7(), true);
        v_items := basalt_meta._revert_execute(p_items);
        RAISE EXCEPTION USING ERRCODE = 'BS099', MESSAGE = 'TRIAL_ROLLED_BACK';
    EXCEPTION WHEN SQLSTATE 'BS099' THEN
        NULL; -- every trial write is undone; the items remain
    END;
    RETURN v_items;
END $$;

CREATE OR REPLACE FUNCTION basalt_meta._revert_trial(p_items basalt_meta.revert_item[], p_role name) RETURNS text[]
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT basalt_meta._revert_text(basalt_meta._revert_trial_items(p_items), p_role)
$$;
