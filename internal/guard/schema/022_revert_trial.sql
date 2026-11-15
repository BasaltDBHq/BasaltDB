-- The revert trial run: the revert writes, the revert row trigger and
-- prepare_revert.

CREATE FUNCTION basalt_meta._revert_running() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT EXISTS (SELECT 1 FROM basalt_meta.revert_running r WHERE r.tx = pg_current_xact_id_if_assigned())
$$;

-- A row written by a revert: it must be the one row the revert is writing
-- now (decision M3-5: a revert never changes a row it did not plan, so a
-- cascade or an app trigger reaching another row raises REVERT_CASCADE,
-- which the revert turns into a CASCADE conflict). No intent, row limits
-- or STALE_READ: the person authorized these rows.
CREATE FUNCTION basalt_meta._guard_revert_row(
    p_table regclass, p_op text, p_depth int, p_old jsonb, p_new jsonb, p_old_xmin xid, p_new_xmin xid
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    r     basalt_meta.revert_running;
    v_key jsonb := basalt_meta._row_key(p_table, coalesce(p_old, p_new));
BEGIN
    SELECT * INTO r FROM basalt_meta.revert_running x WHERE x.tx = pg_current_xact_id();
    IF p_depth > 1 OR r.target_table IS DISTINCT FROM p_table::oid OR r.target_key IS DISTINCT FROM v_key THEN
        RAISE EXCEPTION USING ERRCODE = 'BS009', MESSAGE = 'REVERT_CASCADE',
            DETAIL = format('%s %s %s is not part of the revert', p_op, p_table, v_key);
    END IF;
    PERFORM basalt_meta._append(r.agent, r.change_id, 'ROW_CHANGE', p_table, p_op, v_key, p_old, p_new, p_depth,
        jsonb_build_object('xmin', p_old_xmin::text, 'newXmin', p_new_xmin::text, 'cascaded', false,
                           'revertOf', to_jsonb(r.revert_of)));
END $$;

CREATE OR REPLACE FUNCTION basalt_meta.guard_row() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF (SELECT r.rolsuper FROM pg_roles r WHERE r.rolname = session_user) THEN
        RETURN NULL;
    END IF;
    IF basalt_meta._revert_running() THEN
        PERFORM basalt_meta._guard_revert_row(
            TG_RELID::regclass, TG_OP, pg_trigger_depth(),
            CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END,
            CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END,
            CASE WHEN TG_OP <> 'INSERT' THEN OLD.xmin END,
            CASE WHEN TG_OP <> 'DELETE' THEN NEW.xmin END);
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

-- One inverse write, in its own subtransaction. Returns NULL when it
-- landed, else the SQLSTATE that stopped it (BS098: the row was not
-- there). An UPDATE writes only the columns that differ.
CREATE FUNCTION basalt_meta._revert_write(it basalt_meta.revert_item) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_tbl   text := it.table_oid::regclass::text;
    v_where text;
    v_cols  text;
    v_vals  text;
    v_n     bigint;
BEGIN
    UPDATE basalt_meta.revert_running x SET target_table = it.table_oid, target_key = it.key, revert_of = it.change_ids
     WHERE x.tx = pg_current_xact_id();
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

-- Run the RESTORE items (decision M3-5): deletes (latest change first),
-- updates (latest first), re-inserts (earliest first), with every
-- constraint immediate. A write refused by a foreign key is retried after
-- the rest of its phase until a pass makes no progress, so parents land
-- before children whatever the ledger order. What still fails becomes a
-- conflict.
CREATE FUNCTION basalt_meta._revert_execute(p_items basalt_meta.revert_item[]) RETURNS basalt_meta.revert_item[]
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_items    basalt_meta.revert_item[] := p_items;
    v_pending  int[];
    v_retry    int[];
    v_progress boolean;
    v_state    text;
    v_phase    text;
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
                CASE
                WHEN v_state IS NULL THEN
                    v_progress := true;
                WHEN v_state = '23503' THEN
                    v_retry := v_retry || i;
                ELSE
                    it := v_items[i];
                    it.conflict := CASE v_state WHEN 'BS009' THEN 'CASCADE' WHEN 'BS098' THEN 'ROW_GONE' ELSE 'CONSTRAINT' END;
                    it.sql_state := CASE WHEN it.conflict = 'CONSTRAINT' THEN v_state END;
                    v_items[i] := it;
                END CASE;
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

-- The lines of a revert after a trial run that always rolls back.
CREATE FUNCTION basalt_meta._revert_trial(p_items basalt_meta.revert_item[], p_role name) RETURNS text[]
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_lines text[];
BEGIN
    BEGIN
        INSERT INTO basalt_meta.revert_running (tx, agent, change_id)
        VALUES (pg_current_xact_id(), session_user, basalt_meta._uuidv7());
        v_lines := basalt_meta._revert_text(basalt_meta._revert_execute(p_items), p_role);
        RAISE EXCEPTION USING ERRCODE = 'BS099', MESSAGE = 'TRIAL_ROLLED_BACK';
    EXCEPTION WHEN SQLSTATE 'BS099' THEN
        NULL; -- every trial write is undone; the lines remain
    END;
    RETURN v_lines;
END $$;

-- Agent (MCP preview_revert, basalt revert --dry-run): what reverting the
-- scope would do, from a trial run. Needs a read-write transaction; it
-- leaves nothing behind.
CREATE OR REPLACE FUNCTION basalt_meta.preview_revert(p_scope text, p_scope_id uuid) RETURNS SETOF text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    PERFORM basalt_meta._require_agent();
    RETURN QUERY SELECT u.line
      FROM unnest(basalt_meta._revert_trial(basalt_meta._revert_items(p_scope, p_scope_id, false), session_user))
           WITH ORDINALITY u(line, n)
     ORDER BY u.n;
END $$;

-- Agent, as the CLI's relay: store a revert for the person to sign. The
-- binding is built here, from lines this function computed.
CREATE FUNCTION basalt_meta.prepare_revert(p_scope text, p_scope_id uuid, p_intent text)
RETURNS TABLE (revert_id uuid, binding_text text, expires_at timestamptz, lines text[])
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
#variable_conflict use_column
DECLARE
    c_ttl     constant interval := interval '1 hour';
    v_id      uuid := basalt_meta._uuidv7();
    v_expires timestamptz := now() + c_ttl;
    v_lines   text[];
    v_rows    int;
    v_agents  name[];
    v_hash    bytea;
    v_text    text;
BEGIN
    PERFORM basalt_meta._require_agent();
    PERFORM basalt_meta._check_text('intent', p_intent, 2000, true);
    v_lines := basalt_meta._revert_trial(basalt_meta._revert_items(p_scope, p_scope_id, false), session_user);
    SELECT count(l)::int INTO v_rows FROM unnest(v_lines) l WHERE l::jsonb ->> 'action' = 'RESTORE';
    IF v_rows = 0 THEN
        RAISE EXCEPTION USING ERRCODE = 'BS009', MESSAGE = 'NOTHING_TO_REVERT',
            DETAIL = format('every row of %s %s would be skipped', p_scope, p_scope_id);
    END IF;
    SELECT array_agg(DISTINCT s.agent ORDER BY s.agent) INTO v_agents FROM basalt_meta._revert_scope(p_scope, p_scope_id) s;
    v_hash := sha256(convert_to(array_to_string(v_lines, E'\n'), 'UTF8'));
    v_text := jsonb_build_object(
        'kind', 'REVERT', 'revertId', v_id, 'database', current_database(), 'scope', p_scope, 'scopeId', p_scope_id,
        'agents', to_jsonb(v_agents::text[]), 'intent', p_intent, 'rows', v_rows,
        'skipped', cardinality(v_lines) - v_rows, 'rowsHash', encode(v_hash, 'hex'),
        'expiresAt', to_char(v_expires AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'requestedBy', session_user)::text;
    INSERT INTO basalt_meta.reverts (revert_id, scope, scope_id, agents, requested_by, intent, lines, rows, skipped,
                                     rows_hash, binding_text, binding, expires_at)
    VALUES (v_id, p_scope, p_scope_id, v_agents, session_user, p_intent, v_lines, v_rows, cardinality(v_lines) - v_rows,
            v_hash, v_text, sha256(convert_to(v_text, 'UTF8')), v_expires);
    PERFORM basalt_meta._append(session_user, NULL, 'REVERT_PENDING', NULL, NULL, NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', v_id, 'scope', p_scope, 'scopeId', p_scope_id, 'intent', p_intent,
                           'rows', v_rows, 'skipped', cardinality(v_lines) - v_rows,
                           'rowsHash', encode(v_hash, 'hex'), 'expiresAt', v_expires));
    revert_id := v_id;
    binding_text := v_text;
    expires_at := v_expires;
    lines := v_lines;
    RETURN NEXT;
END $$;

-- The reverts the calling role prepared.
CREATE VIEW basalt_meta.agent_reverts WITH (security_barrier = true) AS
    SELECT r.revert_id, r.scope, r.scope_id, r.agents, r.intent, r.rows, r.skipped,
           CASE WHEN r.applied_at IS NOT NULL THEN 'APPLIED'
                WHEN r.expires_at <= pg_catalog.now() THEN 'EXPIRED'
                ELSE 'PENDING' END AS status,
           r.created_at, r.expires_at, r.applied_at, r.change_id, r.binding_text, r.lines
      FROM basalt_meta.reverts r
     WHERE r.requested_by = session_user;

GRANT SELECT ON basalt_meta.agent_reverts TO {{agents}};
GRANT EXECUTE ON FUNCTION basalt_meta.prepare_revert(text, uuid, text) TO {{agents}};
