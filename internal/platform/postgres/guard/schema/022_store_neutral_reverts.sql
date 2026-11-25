-- Version 10: store-neutral texts. This file: what a person signs for a
-- revert (CONTRACT.md, Revert): lines name the resource, shape and store
-- (the SQLSTATE as store.code), ROW_GONE is TARGET_GONE, and the binding
-- names the store and every agent agent:<name>. The descriptor travels as
-- texts carry it (agents agent:<name>, resources) and is kept in the
-- guard's own form (roles, tables), so the own-work, widened and
-- membership checks are the ones before.

-- The inverse of one chain and its static conflict (CONTRACT.md, Revert,
-- Conflicts), first reason that applies, with the ALREADY_REVERTED lookup
-- through _revert_last. CASCADE and CONSTRAINT need a trial write.
CREATE OR REPLACE FUNCTION basalt_meta._revert_item(c basalt_meta.revert_chain, p_lock boolean) RETURNS basalt_meta.revert_item
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    it     basalt_meta.revert_item;
    v_pk   text[];
    v_gen  text[];
    v_now  jsonb;
    v_xmin text;
    v_left jsonb;
    v_last basalt_meta.ledger;
    v_take jsonb;
BEGIN
    it.table_oid := c.table_oid;
    it.table_name := c.table_name;
    it.cascaded := c.cascaded;
    it.change_ids := c.change_ids;
    it.first_seq := c.first_seq;
    it.last_seq := c.last_seq;
    it.op := CASE WHEN c.first_op = 'INSERT' THEN 'DELETE' WHEN c.last_op = 'DELETE' THEN 'INSERT' ELSE 'UPDATE' END;
    it.key := CASE it.op WHEN 'INSERT' THEN c.orig_key ELSE c.cur_key END;
    it.set := CASE WHEN it.op = 'DELETE' THEN NULL ELSE c.old_row END;

    IF c.pruned THEN
        it.conflict := 'VALUES_PRUNED';
        RETURN it;
    END IF;
    SELECT g.pk_cols INTO v_pk FROM basalt_meta.guarded_tables g WHERE g.table_oid = c.table_oid::regclass;
    IF v_pk IS NULL
       OR (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(it.key) k)
          IS DISTINCT FROM (SELECT array_agg(k ORDER BY k) FROM unnest(v_pk) k)
       OR EXISTS (SELECT 1 FROM jsonb_object_keys(coalesce(c.old_row, '{}'::jsonb)) k
                   WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a
                                      WHERE a.attrelid = c.table_oid AND a.attname = k AND a.attnum > 0
                                        AND NOT a.attisdropped)) THEN
        it.conflict := 'SCHEMA_CHANGED';
        RETURN it;
    END IF;
    SELECT coalesce(array_agg(a.attname::text), '{}') INTO v_gen
      FROM pg_catalog.pg_attribute a
     WHERE a.attrelid = c.table_oid AND a.attnum > 0 AND NOT a.attisdropped AND a.attgenerated <> '';
    it.set := it.set - v_gen; -- generated columns are recomputed, never written (M3-13)

    SELECT f.row_now, f.row_xmin INTO v_now, v_xmin FROM basalt_meta._revert_fetch(c.table_oid, it.key, p_lock) f;
    it.now := v_now;

    v_last := basalt_meta._revert_last(c.table_oid, ARRAY[c.orig_key, c.cur_key], c.last_seq);
    IF v_last.seq IS NOT NULL AND v_last.detail ? 'revertOf'
       AND (v_last.detail -> 'revertOf') ?| c.change_ids::text[] THEN
        it.conflict := 'ALREADY_REVERTED';
        RETURN it;
    END IF;
    IF c.broken THEN
        it.conflict := 'CHANGED_AFTER';
        RETURN it;
    END IF;

    IF it.op = 'INSERT' THEN
        IF v_now IS NOT NULL THEN
            it.conflict := 'KEY_TAKEN';
        END IF;
        RETURN it;
    END IF;
    IF v_now IS NULL THEN
        it.conflict := 'TARGET_GONE';
        RETURN it;
    END IF;
    -- The row as the agent left it: same version and same values (columns
    -- added since are not compared).
    SELECT jsonb_object_agg(k, v_now -> k) INTO v_left FROM jsonb_object_keys(c.new_row) k;
    IF (c.new_xmin IS NOT NULL AND v_xmin IS DISTINCT FROM c.new_xmin) OR v_left IS DISTINCT FROM c.new_row THEN
        it.conflict := 'CHANGED_AFTER';
        RETURN it;
    END IF;
    IF it.op = 'UPDATE' AND c.orig_key <> c.cur_key THEN
        SELECT f.row_now INTO v_take FROM basalt_meta._revert_fetch(c.table_oid, c.orig_key, p_lock) f;
        IF v_take IS NOT NULL THEN
            it.conflict := 'KEY_TAKEN';
        END IF;
    END IF;
    RETURN it;
END $$;

-- Run the RESTORE items (decision M3-5): deletes (latest change first),
-- updates (latest first), re-inserts (earliest first), with every
-- constraint immediate. A write refused by a foreign key is retried after
-- the rest of its phase until a pass makes no progress, so parents land
-- before children whatever the ledger order. What still fails becomes a
-- conflict. Each write that lands is numbered in the order it landed
-- (step).
CREATE OR REPLACE FUNCTION basalt_meta._revert_execute(p_items basalt_meta.revert_item[]) RETURNS basalt_meta.revert_item[]
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
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
                    it.conflict := CASE v_state WHEN 'BS009' THEN 'CASCADE' WHEN 'BS098' THEN 'TARGET_GONE' ELSE 'CONSTRAINT' END;
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

-- Any relay (the engine for the revert page, with the agent credential):
-- verify the person's assertion over a prepared revert and run it in the
-- same call, so there is no signed-but-unapplied revert to replay; for a
-- batched plan, record the signature only (_revert_sign). The revert row is
-- locked before any check, so a rescope and a signature cannot
-- interleave. The binding must carry the stored selection as its select,
-- and the lines are recomputed from that selection, never from the
-- binding. applied_at reads the wall clock.
CREATE OR REPLACE FUNCTION basalt_meta.apply_revert(
    p_revert_id uuid, p_credential_id bytea, p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    r         basalt_meta.reverts;
    v_change  uuid := basalt_meta._uuidv7();
    v_items   basalt_meta.revert_item[];
    v_lines   text[];
    v_rows    int;
    v_skipped jsonb;
    v_detail  text;
BEGIN
    PERFORM basalt_meta._require_agent();
    SELECT * INTO r FROM basalt_meta.reverts x WHERE x.revert_id = p_revert_id FOR UPDATE;
    IF NOT FOUND THEN
        PERFORM basalt_meta._revert_invalid('no such revert');
    END IF;
    IF r.applied_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_invalid('revert already applied');
    END IF;
    IF r.rejected_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_invalid('the person rejected this revert; nothing was reverted');
    END IF;
    IF r.signed_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_invalid('revert already signed; the agent applies it in batches');
    END IF;
    IF r.expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'REVERT_EXPIRED',
            DETAIL = format('revert %s expired at %s; prepare it again', r.revert_id, r.expires_at);
    END IF;
    IF (r.binding_text::jsonb -> 'select') IS DISTINCT FROM basalt_meta._revert_select_text(r.selection) THEN
        PERFORM basalt_meta._revert_invalid('the binding does not carry this revert''s scope; prepare the revert again');
    END IF;
    IF r.rows = 0 THEN
        RAISE EXCEPTION USING ERRCODE = 'BS009', MESSAGE = 'NOTHING_TO_REVERT',
            DETAIL = format('%s %s has no row to restore in this scope', r.scope, r.scope_id);
    END IF;
    BEGIN
        PERFORM basalt_meta._verify_assertion(r.binding, p_credential_id, p_authenticator_data, p_client_data_json, p_signature);
    EXCEPTION WHEN SQLSTATE 'BS005' THEN
        GET STACKED DIAGNOSTICS v_detail = PG_EXCEPTION_DETAIL;
        PERFORM basalt_meta._revert_invalid(v_detail);
    END;
    IF r.batched THEN
        RETURN basalt_meta._revert_sign(r, p_credential_id);
    END IF;

    PERFORM set_config('lock_timeout', '5s', true);
    INSERT INTO basalt_meta.changes (change_id, tx, stmt_ts, agent, intent, op, rows, mode, status,
                                     actor_kind, revert_id, credential_id)
    VALUES (v_change, pg_current_xact_id(), statement_timestamp(), session_user, r.intent, 'REVERT', 0, 'APPLY',
            'APPLIED', 'PERSON', r.revert_id, p_credential_id);
    INSERT INTO basalt_meta.revert_running (tx, agent, change_id) VALUES (pg_current_xact_id(), session_user, v_change);
    v_items := basalt_meta._revert_execute(basalt_meta._revert_items(r.selection, true));
    v_lines := basalt_meta._revert_text(v_items, r.requested_by);
    DELETE FROM basalt_meta.revert_running x WHERE x.tx = pg_current_xact_id();
    IF sha256(convert_to(array_to_string(v_lines, E'\n'), 'UTF8')) <> r.rows_hash THEN
        PERFORM basalt_meta._revert_invalid('rows changed since the preview; nothing was reverted, prepare the revert again');
    END IF;

    SELECT count(x.table_oid)::int INTO v_rows FROM unnest(v_items) x WHERE x.conflict IS NULL;
    UPDATE basalt_meta.changes x SET rows = v_rows WHERE x.change_id = v_change;
    -- A change is REVERTED when none of its rows was skipped and no table
    -- filter left one of its rows out; otherwise it stays APPLIED and names
    -- the revert (M3-8).
    UPDATE basalt_meta.changes c
       SET reverted_by = coalesce(c.reverted_by, '{}'::uuid[]) || v_change,
           status = CASE WHEN EXISTS (SELECT 1 FROM unnest(v_items) x WHERE x.conflict IS NOT NULL AND c.change_id = ANY (x.change_ids))
                              OR NOT basalt_meta._revert_whole(r.selection, c.change_id)
                         THEN c.status ELSE 'REVERTED' END
     WHERE c.change_id IN (SELECT s FROM basalt_meta._revert_covered(r.selection) s)
       AND (EXISTS (SELECT 1 FROM unnest(v_items) x WHERE x.conflict IS NULL AND c.change_id = ANY (x.change_ids))
            OR NOT EXISTS (SELECT 1 FROM unnest(v_items) x WHERE c.change_id = ANY (x.change_ids)));
    UPDATE basalt_meta.reverts x SET applied_at = clock_timestamp(), credential_id = p_credential_id, change_id = v_change
     WHERE x.revert_id = r.revert_id;

    SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
               'resource', l -> 'resource', 'key', l -> 'key', 'rowHash', l -> 'rowHash',
               'conflict', l -> 'conflict', 'sqlState', l -> 'store' -> 'code')) ORDER BY n), '[]'::jsonb)
      INTO v_skipped
      FROM unnest(v_lines) WITH ORDINALITY u(t, n) CROSS JOIN LATERAL (SELECT u.t::jsonb AS l) j
     WHERE l ->> 'action' = 'SKIP';
    PERFORM basalt_meta._append(session_user, v_change, 'REVERTED', NULL, 'REVERT', NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', r.revert_id, 'scope', r.scope, 'scopeId', r.scope_id, 'select', r.selection,
                           'intent', r.intent, 'credentialId', encode(p_credential_id, 'hex'),
                           'binding', encode(r.binding, 'hex'), 'rows', v_rows, 'skipped', v_skipped));
    RETURN jsonb_build_object('changeId', v_change, 'rows', v_rows, 'skipped', cardinality(v_lines) - v_rows);
END $$;

-- One revert line (CONTRACT.md, Revert), redacted unless _line_visible, in
-- the store-neutral form (CONTRACT.md, Stores): shape RECORD, store {kind,
-- verb, code} with the inverse write as verb and the SQLSTATE that stopped
-- a trial write as code, and resource.
CREATE OR REPLACE FUNCTION basalt_meta._revert_line(it basalt_meta.revert_item, p_role name) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT CASE WHEN basalt_meta._line_visible(it, p_role)
        THEN jsonb_build_object('op', it.op, 'key', it.key, 'now', it.now, 'set', it.set, 'resource', it.table_name,
                                'shape', 'RECORD',
                                'store', jsonb_build_object('kind', 'POSTGRES', 'verb', it.op, 'code', it.sql_state),
                                'action', CASE WHEN it.conflict IS NULL THEN 'RESTORE' ELSE 'SKIP' END,
                                'cascaded', it.cascaded, 'conflict', it.conflict,
                                'changeIds', to_jsonb(it.change_ids))::text
        ELSE jsonb_build_object('op', it.op, 'resource', it.table_name, 'shape', 'RECORD',
                                'store', jsonb_build_object('kind', 'POSTGRES', 'verb', it.op, 'code', it.sql_state),
                                'action', CASE WHEN it.conflict IS NULL THEN 'RESTORE' ELSE 'SKIP' END,
                                'rowHash', encode(sha256(convert_to(jsonb_build_array(it.key, it.now, it.set)::text, 'UTF8')), 'hex'),
                                'cascaded', it.cascaded, 'conflict', it.conflict, 'redacted', true,
                                'changeIds', to_jsonb(it.change_ids))::text
    END
$$;

-- The skipped lines of a plan as the preparing role saw them, for ledger
-- details: resource, key or row hash, reason; no values.
CREATE OR REPLACE FUNCTION basalt_meta._revert_skips(p_revert uuid, p_lines int[]) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
               'line', l.line_no, 'resource', l.line::jsonb -> 'resource', 'key', l.line::jsonb -> 'key',
               'rowHash', l.line::jsonb -> 'rowHash', 'conflict', l.conflict, 'sqlState', l.sql_state))
             ORDER BY l.line_no), '[]'::jsonb)
      FROM basalt_meta.revert_lines l
     WHERE l.revert_id = p_revert AND l.outcome = 'SKIPPED' AND (p_lines IS NULL OR l.line_no = ANY (p_lines))
$$;

-- The person's signature over a batched plan (decision N12-6): open the
-- revert's change record, mark the SKIP lines skipped, start the 24-hour
-- window (N12-2), signed_at and the window from one reading of the wall
-- clock, and record REVERT_SIGNED. No row of the person's tables is
-- written here.
CREATE OR REPLACE FUNCTION basalt_meta._revert_sign(r basalt_meta.reverts, p_credential_id bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_window   constant interval := interval '24 hours';
    v_change   uuid := basalt_meta._uuidv7();
    v_signed   timestamptz := clock_timestamp();
    v_apply_by timestamptz := v_signed + c_window;
    v_progress record;
BEGIN
    INSERT INTO basalt_meta.changes (change_id, tx, stmt_ts, agent, intent, op, rows, mode, status,
                                     actor_kind, revert_id, credential_id)
    VALUES (v_change, pg_current_xact_id(), statement_timestamp(), session_user, r.intent, 'REVERT', 0, 'APPLY',
            'APPLIED', 'PERSON', r.revert_id, p_credential_id);
    UPDATE basalt_meta.revert_lines l
       SET outcome = 'SKIPPED', batch = 0, conflict = l.line::jsonb ->> 'conflict', sql_state = l.line::jsonb -> 'store' ->> 'code'
     WHERE l.revert_id = r.revert_id AND l.line::jsonb ->> 'action' = 'SKIP';
    UPDATE basalt_meta.reverts x
       SET signed_at = v_signed, apply_by = v_apply_by, credential_id = p_credential_id, change_id = v_change
     WHERE x.revert_id = r.revert_id;
    SELECT * INTO v_progress FROM basalt_meta._revert_progress(r.revert_id);
    PERFORM basalt_meta._append(session_user, v_change, 'REVERT_SIGNED', NULL, 'REVERT', NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', r.revert_id, 'scope', r.scope, 'scopeId', r.scope_id, 'intent', r.intent,
                           'credentialId', encode(p_credential_id, 'hex'), 'binding', encode(r.binding, 'hex'),
                           'lines', r.rows + r.skipped, 'rows', r.rows,
                           'skipped', basalt_meta._revert_skips(r.revert_id, NULL), 'applyBy', v_apply_by));
    RETURN jsonb_build_object('changeId', v_change, 'rows', 0, 'skipped', v_progress.skipped, 'batched', true,
                              'pending', v_progress.pending,
                              'applyBy', to_char(v_apply_by AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
END $$;

-- The descriptor checked for shape and normalized (CONTRACT.md, The scope
-- descriptor), in the form texts carry it: agents agent:<name>, resources
-- schema.table names. Every key present, lists sorted and deduplicated,
-- null for all, ids in canonical form. Reads nothing but its argument, so a
-- refusal here says nothing about any data: SHAPE, NAME (a resources entry
-- that is not one schema.table name), STORE_RESERVED (RS-4) or FILTER_CAP
-- (at most 20 runs and 20 resources). _revert_select_internal maps it to
-- the guard's own form.
CREATE OR REPLACE FUNCTION basalt_meta._revert_select_norm(p jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_max_filter constant int  := 20; -- runs and resources in a descriptor (owner, Q10)
    c_max_name   constant int  := 63; -- NAMEDATALEN - 1
    c_agent      constant text := '^agent:[a-z][a-z0-9_]*$';
    c_max_shown  constant int  := 127; -- the longest schema.table name, schema and table c_max_name each
    c_uuid       constant text := '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$';
    c_table      constant text := '^[^.\s]+\.[^.\s]+$';
    v_key  text;
    v_list text;
    v_bad  text;
BEGIN
    IF jsonb_typeof(p) IS DISTINCT FROM 'object' THEN
        PERFORM basalt_meta._scope_refused('SHAPE', 'the scope descriptor is a JSON object');
    END IF;
    IF p ? 'store' THEN
        PERFORM basalt_meta._scope_refused('STORE_RESERVED', 'store is reserved for multi-database work; leave it out');
    END IF;
    SELECT k INTO v_key FROM pg_catalog.jsonb_object_keys(p) k
     WHERE k NOT IN ('scope', 'scopeId', 'agents', 'runs', 'resources') ORDER BY k LIMIT 1;
    IF FOUND THEN
        PERFORM basalt_meta._scope_refused('SHAPE', 'the scope descriptor has only scope, scopeId, agents, runs and resources');
    END IF;
    FOREACH v_key IN ARRAY ARRAY['scope', 'scopeId', 'agents', 'runs', 'resources'] LOOP
        IF NOT p ? v_key THEN
            PERFORM basalt_meta._scope_refused('SHAPE', format('%s is required (null for all)', v_key));
        END IF;
    END LOOP;
    IF jsonb_typeof(p -> 'scope') IS DISTINCT FROM 'string' OR p ->> 'scope' NOT IN ('CHANGE', 'RUN', 'TASK') THEN
        PERFORM basalt_meta._scope_refused('SHAPE', 'scope is CHANGE, RUN or TASK');
    END IF;
    IF jsonb_typeof(p -> 'scopeId') IS DISTINCT FROM 'string' OR p ->> 'scopeId' !~ c_uuid THEN
        PERFORM basalt_meta._scope_refused('SHAPE', 'scopeId is a uuid');
    END IF;
    FOREACH v_list IN ARRAY ARRAY['agents', 'runs', 'resources'] LOOP
        CONTINUE WHEN jsonb_typeof(p -> v_list) = 'null';
        IF jsonb_typeof(p -> v_list) IS DISTINCT FROM 'array' OR jsonb_array_length(p -> v_list) = 0 THEN
            PERFORM basalt_meta._scope_refused('SHAPE', format('%s is null (all) or a list of at least one', v_list));
        END IF;
        IF v_list <> 'agents' AND jsonb_array_length(p -> v_list) > c_max_filter THEN
            PERFORM basalt_meta._scope_refused('FILTER_CAP', format('%s has at most %s entries; leave it null for all', v_list, c_max_filter));
        END IF;
        IF EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(p -> v_list) e
                    WHERE jsonb_typeof(e) IS DISTINCT FROM 'string'
                       OR CASE v_list WHEN 'agents' THEN (e #>> '{}') !~ c_agent OR length(e #>> '{}') > c_max_name + 6
                                      WHEN 'runs' THEN (e #>> '{}') !~ c_uuid
                                      ELSE false END) THEN
            PERFORM basalt_meta._scope_refused('SHAPE', CASE v_list WHEN 'agents' THEN 'agents are agent:<name> names'
                                                                     WHEN 'runs' THEN 'runs are run ids'
                                                                     ELSE 'resources are schema.table names' END);
        END IF;
        -- Every entry is a string here. The first, in the caller's order,
        -- that is not one schema.table name is named, cut to the longest
        -- name there is.
        IF v_list = 'resources' THEN
            SELECT e INTO v_bad FROM pg_catalog.jsonb_array_elements_text(p -> 'resources') WITH ORDINALITY AS t(e, n)
             WHERE e !~ c_table ORDER BY n LIMIT 1;
            IF FOUND THEN
                IF length(v_bad) > c_max_shown THEN
                    v_bad := left(v_bad, c_max_shown) || '...';
                END IF;
                PERFORM basalt_meta._scope_refused('NAME', format('%s is not a schema.table name', v_bad));
            END IF;
        END IF;
    END LOOP;
    IF jsonb_typeof(p -> 'runs') = 'array' AND p ->> 'scope' <> 'TASK' THEN
        PERFORM basalt_meta._scope_refused('SHAPE', 'runs is only for a TASK scope: a change or a run is one run already');
    END IF;
    RETURN jsonb_build_object(
        'scope', p ->> 'scope',
        'scopeId', ((p ->> 'scopeId')::uuid)::text,
        'agents', basalt_meta._revert_select_list(p -> 'agents'),
        'runs', CASE WHEN jsonb_typeof(p -> 'runs') = 'array'
                     THEN basalt_meta._revert_select_list(
                              (SELECT jsonb_agg(((e)::uuid)::text) FROM pg_catalog.jsonb_array_elements_text(p -> 'runs') e))
                     ELSE 'null'::jsonb END,
        'resources', basalt_meta._revert_select_list(p -> 'resources'));
END $$;

-- The guard's own form of a normalized descriptor (_revert_select_norm):
-- agents as roles, from the record of agent names, and the resources as
-- tables. reverts.selection, ceiling and proposed hold this form, so every
-- own-work, widened and membership check compares roles with session_user
-- as before. An unknown agent stays as given and matches no role.
CREATE OR REPLACE FUNCTION basalt_meta._revert_select_internal(p jsonb) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT jsonb_build_object(
        'scope', p -> 'scope', 'scopeId', p -> 'scopeId', 'runs', p -> 'runs', 'tables', p -> 'resources',
        'agents', CASE WHEN jsonb_typeof(p -> 'agents') = 'array'
                       THEN (SELECT to_jsonb(array_agg(r ORDER BY r COLLATE "C"))
                               FROM (SELECT DISTINCT basalt_meta._agent_role(a) AS r
                                       FROM jsonb_array_elements_text(p -> 'agents') a) s)
                       ELSE 'null'::jsonb END)
$$;

-- A descriptor in the guard's own form as texts carry it (CONTRACT.md,
-- Stores, Agent names): agents agent:<name>, sorted, and resources.
CREATE OR REPLACE FUNCTION basalt_meta._revert_select_text(p jsonb) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT jsonb_build_object(
        'scope', p -> 'scope', 'scopeId', p -> 'scopeId', 'runs', p -> 'runs', 'resources', p -> 'tables',
        'agents', CASE WHEN jsonb_typeof(p -> 'agents') = 'array'
                       THEN (SELECT to_jsonb(array_agg(t ORDER BY t COLLATE "C"))
                               FROM (SELECT DISTINCT basalt_meta._agent_text(a::name) AS t
                                       FROM jsonb_array_elements_text(p -> 'agents') a) s)
                       ELSE 'null'::jsonb END)
$$;

-- The descriptor p as an agent role's own proposal (RS-1), for
-- preview_revert and prepare_revert: normalized, then refused with the
-- reason _revert_own_refusal gives (an undo of a widened revert is
-- NOT_OWN_CHANGE). Refusals name only what the caller sent, with one fixed
-- text per kind, so another agent's change, run or table reads like one
-- that does not exist.
CREATE OR REPLACE FUNCTION basalt_meta._revert_own_select(p jsonb) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_sel     jsonb := basalt_meta._revert_select_internal(basalt_meta._revert_select_norm(p));
    v_refusal text[] := basalt_meta._revert_own_refusal(v_sel, session_user);
BEGIN
    IF v_refusal IS NOT NULL THEN
        PERFORM basalt_meta._scope_refused(v_refusal[1], v_refusal[2]);
    END IF;
    RETURN v_sel;
END $$;

-- Why the normalized descriptor p_sel is not p_role's own work (RS-1), as
-- {detail, hint}, or NULL when it is: agents exactly [p_role], its own
-- change or run or a task it ran in, every listed run and table inside
-- that work. A yes or no that raises nothing, so rescope_revert can ask
-- without answering. One fixed text per kind: another agent's change, run
-- or table reads like one that does not exist.
--
-- The change of a widened revert (op REVERT, recorded under the role that
-- relayed it) is not the role's own: undoing it would show the role the
-- other agents' rows and old values the person added (RS-5).
CREATE OR REPLACE FUNCTION basalt_meta._revert_own_refusal(p_sel jsonb, p_role name) RETURNS text[]
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_id      uuid := (p_sel ->> 'scopeId')::uuid;
    v_own     jsonb := p_sel || jsonb_build_object('runs', NULL, 'tables', NULL);
    v_refused text[];
BEGIN
    IF p_sel -> 'agents' IS DISTINCT FROM jsonb_build_array(p_role::text) THEN
        RETURN ARRAY['FILTER', 'agents is exactly your own agent:<name>: an agent proposes only its own work'];
    END IF;
    CASE p_sel ->> 'scope'
    WHEN 'CHANGE' THEN
        IF NOT EXISTS (SELECT 1 FROM basalt_meta.changes c
                        WHERE c.change_id = v_id AND c.agent = p_role
                          AND NOT (c.op = 'REVERT' AND EXISTS (SELECT 1 FROM basalt_meta.reverts r
                                                                WHERE r.revert_id = c.revert_id AND r.widened))) THEN
            RETURN ARRAY['NOT_OWN_CHANGE', format('change %s is not one of your changes', v_id)];
        END IF;
    WHEN 'RUN' THEN
        IF NOT EXISTS (SELECT 1 FROM basalt_meta.runs r WHERE r.run_id = v_id AND r.agent = p_role) THEN
            RETURN ARRAY['NOT_OWN_RUN', format('run %s is not one of your runs', v_id)];
        END IF;
    ELSE
        IF NOT EXISTS (SELECT 1 FROM basalt_meta.runs r WHERE r.task_id = v_id AND r.agent = p_role) THEN
            RETURN ARRAY['NOT_OWN_TASK', format('you have no run in task %s', v_id)];
        END IF;
    END CASE;
    v_refused := ARRAY(
        SELECT format('run %s is not one of your runs in task %s', u.run, v_id)
          FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(p_sel -> 'runs') = 'array' THEN p_sel -> 'runs' ELSE '[]' END) u(run)
         WHERE NOT EXISTS (SELECT 1 FROM basalt_meta.runs r
                            WHERE r.run_id = u.run::uuid AND r.task_id = v_id AND r.agent = p_role)
        UNION ALL
        SELECT format('%s has no change of yours in this scope', u.tbl)
          FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(p_sel -> 'tables') = 'array' THEN p_sel -> 'tables' ELSE '[]' END) u(tbl)
         WHERE NOT EXISTS (SELECT 1 FROM basalt_meta._revert_rows(v_own) x WHERE x.table_name = u.tbl));
    IF cardinality(v_refused) > 0 THEN
        RETURN ARRAY['FILTER', array_to_string(v_refused, '; ')];
    END IF;
    RETURN NULL;
END $$;

-- Scope membership (check order step 4), reached only by the requesting
-- role about its own work or by a proven or token-bearing call. The scope
-- is the proposal's, or the run or task the proposal's change or run
-- belongs to; each listed agent other than p_role has a change in it
-- (DESCRIPTOR); each listed run is a run of the task by a selected agent
-- and each listed table was written in it by them (FILTER).
CREATE OR REPLACE FUNCTION basalt_meta._revert_select_members(p_sel jsonb, p_proposed jsonb, p_role name) RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_id       uuid := (p_sel ->> 'scopeId')::uuid;
    v_prop_id  uuid := (p_proposed ->> 'scopeId')::uuid;
    v_all      jsonb := p_sel || jsonb_build_object('agents', NULL, 'runs', NULL, 'tables', NULL);
    v_refused  text[];
BEGIN
    IF NOT (p_sel ->> 'scope' = p_proposed ->> 'scope' AND v_id = v_prop_id
            OR p_sel ->> 'scope' = 'TASK' AND p_proposed ->> 'scope' = 'RUN'
               AND EXISTS (SELECT 1 FROM basalt_meta.runs r WHERE r.run_id = v_prop_id AND r.task_id = v_id)
            OR p_sel ->> 'scope' = 'TASK' AND p_proposed ->> 'scope' = 'CHANGE'
               AND EXISTS (SELECT 1 FROM basalt_meta.changes c WHERE c.change_id = v_prop_id AND c.task_id = v_id)
            OR p_sel ->> 'scope' = 'RUN' AND p_proposed ->> 'scope' = 'CHANGE'
               AND EXISTS (SELECT 1 FROM basalt_meta.changes c WHERE c.change_id = v_prop_id AND c.run_id = v_id)) THEN
        PERFORM basalt_meta._scope_refused('DESCRIPTOR',
            'the scope is the proposal''s change, run or task, or the run or task the proposal belongs to');
    END IF;
    v_refused := ARRAY(
        SELECT format('agent %s has no change in this scope',
                      coalesce((SELECT 'agent:' || n.name FROM basalt_meta.agent_names n WHERE n.role::text = u.a), u.a))
          FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(p_sel -> 'agents') = 'array' THEN p_sel -> 'agents' ELSE '[]' END) u(a)
         WHERE u.a <> p_role::text
           AND NOT EXISTS (SELECT 1 FROM basalt_meta._revert_scope(v_all) s WHERE s.agent::text = u.a));
    IF cardinality(v_refused) > 0 THEN
        PERFORM basalt_meta._scope_refused('DESCRIPTOR', array_to_string(v_refused, '; '));
    END IF;
    v_refused := ARRAY(
        SELECT format('run %s is not a run in task %s', u.run, v_id)
          FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(p_sel -> 'runs') = 'array' THEN p_sel -> 'runs' ELSE '[]' END) u(run)
         WHERE NOT EXISTS (SELECT 1 FROM basalt_meta.runs r
                            WHERE r.run_id = u.run::uuid AND r.task_id = v_id
                              AND (jsonb_typeof(p_sel -> 'agents') IS DISTINCT FROM 'array' OR (p_sel -> 'agents') ? r.agent::text))
        UNION ALL
        SELECT format('%s has no change in this scope', u.tbl)
          FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(p_sel -> 'tables') = 'array' THEN p_sel -> 'tables' ELSE '[]' END) u(tbl)
         WHERE NOT EXISTS (SELECT 1 FROM basalt_meta._revert_rows(p_sel || jsonb_build_object('tables', NULL)) x
                            WHERE x.table_name = u.tbl));
    IF cardinality(v_refused) > 0 THEN
        PERFORM basalt_meta._scope_refused('FILTER', array_to_string(v_refused, '; '));
    END IF;
END $$;

-- What the person may pick from inside the select they proved (CONTRACT.md,
-- revert-scope-response.schema.json): the agents with changes in it, their
-- runs and the resources written, agents named agent:<name>. Returned only
-- to a proven or token-bearing rescope_revert call; no view holds it.
CREATE OR REPLACE FUNCTION basalt_meta._revert_catalog(p_sel jsonb) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    WITH s AS (SELECT c.change_id, c.agent, c.run_id FROM basalt_meta._revert_scope(p_sel) x
                 JOIN basalt_meta.changes c ON c.change_id = x.change_id)
    SELECT pg_catalog.jsonb_build_object(
        'agents', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('agent', basalt_meta._agent_text(a.agent), 'changes', a.n) ORDER BY basalt_meta._agent_text(a.agent) COLLATE "C")
                              FROM (SELECT s.agent, pg_catalog.count(s.change_id)::int AS n FROM s GROUP BY s.agent) a), '[]'::jsonb),
        'runs', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                                     'runId', u.run_id, 'agent', basalt_meta._agent_text(u.agent), 'changes', u.n,
                                     'startedAt', pg_catalog.to_char(r.started_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
                                 ORDER BY u.run_id)
                            FROM (SELECT s.run_id, s.agent, pg_catalog.count(s.change_id)::int AS n FROM s
                                   WHERE s.run_id IS NOT NULL GROUP BY s.run_id, s.agent) u
                            JOIN basalt_meta.runs r ON r.run_id = u.run_id), '[]'::jsonb),
        'resources', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('resource', t.table_name, 'rows', t.n) ORDER BY t.table_name COLLATE "C")
                              FROM (SELECT x.table_name, pg_catalog.count(x.seq)::int AS n FROM basalt_meta._revert_rows(p_sel) x
                                     GROUP BY x.table_name) t), '[]'::jsonb),
        -- Each change in the scope to the agent that made it, so the page
        -- tags every row of a multi-agent select (Q-11).
        'changeAgents', coalesce((SELECT pg_catalog.jsonb_object_agg(s.change_id::text, basalt_meta._agent_text(s.agent)) FROM s), '{}'::jsonb))
$$;

-- Lines per agent role among items, RESTORE and SKIP: a line counts for
-- every agent with a change in it. The binding's agentRows, keyed
-- agent:<name>.
CREATE OR REPLACE FUNCTION basalt_meta._revert_agent_rows(p_items basalt_meta.revert_item[]) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce(jsonb_object_agg(basalt_meta._agent_text(a.agent), a.n), '{}'::jsonb)
      FROM (SELECT c.agent, count(DISTINCT x.first_seq)::int AS n
              FROM unnest(p_items) x
             CROSS JOIN LATERAL unnest(x.change_ids) u(cid)
              JOIN basalt_meta.changes c ON c.change_id = u.cid
             GROUP BY c.agent) a
$$;

-- The binding text the person signs (CONTRACT.md, Revert): the scope as
-- select, proposed only when a rescope changed it, widened, and agentRows
-- only when widened; batched and sampleHash for a large plan.
CREATE OR REPLACE FUNCTION basalt_meta._revert_binding(
    p_id uuid, p_select jsonb, p_proposed jsonb, p_requested_by name, p_intent text, p_rows int, p_skipped int,
    p_rows_hash bytea, p_expires timestamptz, p_sample_hash bytea, p_agent_rows jsonb
) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT (jsonb_build_object(
        'kind', 'REVERT', 'revertId', p_id,
        'store', jsonb_build_object('kind', 'POSTGRES', 'name', current_database()),
        'select', basalt_meta._revert_select_text(p_select),
        'widened', basalt_meta._widened(p_select, p_requested_by), 'intent', p_intent, 'rows', p_rows,
        'skipped', p_skipped, 'rowsHash', encode(p_rows_hash, 'hex'),
        'expiresAt', to_char(p_expires AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'requestedBy', basalt_meta._agent_text(p_requested_by))
        || CASE WHEN p_proposed IS DISTINCT FROM p_select
                THEN jsonb_build_object('proposed', basalt_meta._revert_select_text(p_proposed))
                ELSE '{}'::jsonb END
        || CASE WHEN basalt_meta._widened(p_select, p_requested_by) THEN jsonb_build_object('agentRows', p_agent_rows)
                ELSE '{}'::jsonb END
        || CASE WHEN p_sample_hash IS NOT NULL
                THEN jsonb_build_object('batched', true, 'sampleHash', encode(p_sample_hash, 'hex'))
                ELSE '{}'::jsonb END)::text
$$;

-- Agent, for the engine's scope route (CONTRACT.md, Rescope, widen and
-- reject): change the scope of the caller's own pending revert. In this
-- order, stopping at the first failure:
--   1. shape, from p_select alone (BS011 SHAPE, STORE_RESERVED, FILTER_CAP);
--   2. own work: a yes or no that raises nothing;
--   3. a proof (p_proof and p_rescope_key, against the current nonce, which
--      it replaces), or, while nobody widened the revert, own work, or the
--      scope token p_token with the select inside the ceiling; every
--      failure is REVERT_INVALID WIDEN_REFUSED;
--   4. scope membership (BS011 DESCRIPTOR, FILTER).
-- Then the lines are rebuilt and REVERT_RESCOPED is appended with the path
-- (via). A proven call sets the ceiling and returns a new scope token
-- (only its hash is kept); a proven or token-bearing call also gets the
-- catalog. The link secret never reaches Postgres: only the key the engine
-- derived from it, of which only sha256 is recorded.
CREATE OR REPLACE FUNCTION basalt_meta.rescope_revert(
    p_revert_id uuid, p_select jsonb, p_proof jsonb, p_rescope_key bytea, p_token bytea
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    r       basalt_meta.reverts;
    v_text  jsonb;
    v_sel   jsonb;
    v_via   text;
    v_token bytea;
    v_out   basalt_meta.reverts;
BEGIN
    PERFORM basalt_meta._require_agent();
    v_text := basalt_meta._revert_select_norm(p_select);
    v_sel := basalt_meta._revert_select_internal(v_text);
    r := basalt_meta._revert_lock_pending(p_revert_id);
    CASE
    WHEN p_proof IS NOT NULL THEN
        IF NOT basalt_meta._rescope_proven(r, v_text, p_proof, p_rescope_key) THEN
            PERFORM basalt_meta._widen_refused();
        END IF;
        v_via := 'PROOF';
    WHEN r.ceiling IS NULL AND basalt_meta._revert_own_refusal(v_sel, r.requested_by) IS NULL THEN
        v_via := 'OWN_WORK';
    WHEN r.ceiling IS NOT NULL AND p_token IS NOT NULL AND sha256(p_token) = r.scope_token_hash
         AND basalt_meta._revert_select_within(v_sel, r.ceiling) THEN
        v_via := 'SCOPE_TOKEN';
    ELSE
        PERFORM basalt_meta._widen_refused();
    END CASE;
    PERFORM basalt_meta._revert_select_members(v_sel, r.proposed, r.requested_by);

    v_out := basalt_meta._revert_rebuild(r, v_sel);
    IF v_via = 'PROOF' THEN
        v_token := basalt_meta._revert_nonce();
        UPDATE basalt_meta.reverts x
           SET ceiling = v_sel, scope_token_hash = sha256(v_token), rescope_nonce = basalt_meta._revert_nonce()
         WHERE x.revert_id = r.revert_id;
    END IF;
    UPDATE basalt_meta.reverts x SET rescoped = x.rescoped + 1 WHERE x.revert_id = r.revert_id
    RETURNING x.* INTO v_out;
    PERFORM basalt_meta._append(session_user, NULL, 'REVERT_RESCOPED', NULL, NULL, NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', r.revert_id, 'oldSelect', r.selection, 'select', v_sel,
                           'oldRowsHash', encode(r.rows_hash, 'hex'), 'rowsHash', encode(v_out.rows_hash, 'hex'),
                           'via', v_via)
        || CASE WHEN v_via = 'PROOF'
                THEN jsonb_build_object('credentialId', encode(basalt_meta._b64url_decode(p_proof ->> 'credentialId'), 'hex'),
                                        'rescopeKeyHash', encode(sha256(p_rescope_key), 'hex'))
                ELSE '{}'::jsonb END);
    RETURN basalt_meta._revert_rescoped(v_out)
        || CASE WHEN v_via = 'OWN_WORK' THEN '{}'::jsonb
                ELSE jsonb_build_object('catalog', basalt_meta._revert_catalog(v_out.ceiling)) END
        || CASE WHEN v_via = 'PROOF' THEN jsonb_build_object('scopeToken', basalt_meta._b64url(v_token))
                ELSE '{}'::jsonb END;
END $$;

-- Relay of the revert page's reveal (POST …/reveal): with the person's
-- proof and key, the values of the revert's redacted lines that the
-- request carries (every line, or a large plan's sample). Locks the revert
-- row first, so it serializes with apply_revert, rescope_revert,
-- reset_revert and reject_revert.
CREATE OR REPLACE FUNCTION basalt_meta.reveal_revert_rows(p_revert_id uuid, p_proof jsonb, p_reveal_key bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    r         basalt_meta.reverts;
    v_items   basalt_meta.revert_item[];
    v_wanted  int;
    v_rows    jsonb;
    v_changed boolean;
BEGIN
    PERFORM basalt_meta._require_agent();
    SELECT * INTO r FROM basalt_meta.reverts x
     WHERE x.revert_id = p_revert_id AND x.requested_by = session_user FOR UPDATE;
    IF NOT FOUND THEN
        PERFORM basalt_meta._revert_invalid('no such revert');
    END IF;
    IF r.applied_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_invalid('revert already applied');
    END IF;
    IF r.rejected_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_invalid('the person rejected this revert; nothing was reverted');
    END IF;
    IF r.signed_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_invalid('revert already signed');
    END IF;
    IF r.expires_at <= pg_catalog.clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'REVERT_EXPIRED',
            DETAIL = pg_catalog.format('revert %s expired at %s; prepare it again', r.revert_id, r.expires_at);
    END IF;
    IF NOT basalt_meta._reveal_proven('REVERT', r.revert_id, r.reveal_nonce, r.rows_hash, p_proof, p_reveal_key) THEN
        PERFORM basalt_meta._reveal_refused('REVERT_INVALID');
    END IF;
    UPDATE basalt_meta.reverts x SET reveal_nonce = basalt_meta._revert_nonce() WHERE x.revert_id = r.revert_id;

    -- The redacted lines of the request, by their 0-based index.
    SELECT pg_catalog.count(u.n)::int INTO v_wanted
      FROM pg_catalog.unnest(r.lines) WITH ORDINALITY u(t, n)
     WHERE (u.t::jsonb -> 'redacted') = 'true'::jsonb;

    -- Each line's row now: from its stored chain for a large plan, else
    -- from the revert's selection, as prepare_revert built it.
    IF r.batched THEN
        v_items := ARRAY(SELECT basalt_meta._revert_item(rl.chain, false)
                           FROM basalt_meta.revert_lines rl
                          WHERE rl.revert_id = r.revert_id AND rl.line = ANY (r.lines)
                            AND (rl.line::jsonb -> 'redacted') = 'true'::jsonb);
    ELSE
        v_items := ARRAY(SELECT basalt_meta._revert_item(x, false)
                           FROM basalt_meta._revert_chains(r.selection) x
                          WHERE NOT (x.first_op = 'INSERT' AND x.last_op = 'DELETE'));
    END IF;

    WITH wanted AS (
        SELECT (u.n - 1)::int AS line, u.t::jsonb ->> 'rowHash' AS row_hash, u.t::jsonb ->> 'resource' AS table_name
          FROM pg_catalog.unnest(r.lines) WITH ORDINALITY u(t, n)
         WHERE (u.t::jsonb -> 'redacted') = 'true'::jsonb
    )
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('line', w.line) || basalt_meta._reveal_revert_line(m.it)
                                ORDER BY w.line)
      INTO v_rows
      FROM wanted w
      JOIN LATERAL (SELECT i AS it FROM pg_catalog.unnest(v_items) i
                     WHERE i.table_name = w.table_name
                       AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
                               pg_catalog.jsonb_build_array(i.key, i.now, i.set)::text, 'UTF8')), 'hex') = w.row_hash
                     LIMIT 1) m ON true;
    v_changed := coalesce(pg_catalog.jsonb_array_length(v_rows), 0) <> v_wanted;

    PERFORM basalt_meta._append(session_user, NULL, 'ROWS_REVEALED', NULL, NULL, NULL, NULL, NULL, NULL,
        pg_catalog.jsonb_build_object('kind', 'REVERT', 'id', r.revert_id,
            'credentialId', pg_catalog.encode(basalt_meta._b64url_decode(p_proof ->> 'credentialId'), 'hex'),
            'rows', v_wanted)
        || CASE WHEN v_changed THEN pg_catalog.jsonb_build_object('rowsChanged', true) ELSE '{}'::jsonb END);
    IF v_changed THEN
        RETURN pg_catalog.jsonb_build_object('rowsChanged', true);
    END IF;
    RETURN pg_catalog.jsonb_build_object('rows', coalesce(v_rows, '[]'::jsonb));
END $$;

-- The reverts the calling role prepared, with their status (REJECTED
-- included), the selection and widened. A revert widened beyond the role's
-- own work shows the role no binding, selection, agents or lines (RS-5).
CREATE OR REPLACE VIEW basalt_meta.agent_reverts WITH (security_barrier = true) AS
    SELECT r.revert_id, r.scope, r.scope_id, CASE WHEN r.widened THEN NULL ELSE r.agents END AS agents,
           r.intent, r.rows, r.skipped,
           CASE WHEN r.applied_at IS NOT NULL THEN 'APPLIED'
                WHEN r.rejected_at IS NOT NULL THEN 'REJECTED'
                WHEN r.signed_at IS NOT NULL AND r.apply_by > pg_catalog.now() THEN 'APPLYING'
                WHEN r.signed_at IS NOT NULL THEN 'EXPIRED'
                WHEN r.expires_at <= pg_catalog.now() THEN 'EXPIRED'
                ELSE 'PENDING' END AS status,
           r.created_at, r.expires_at, r.applied_at, r.change_id,
           CASE WHEN r.widened THEN NULL ELSE r.binding_text END AS binding_text,
           CASE WHEN r.widened THEN NULL ELSE r.lines END AS lines,
           r.batched, r.signed_at, r.apply_by, r.batches, p.restored, p.skipped AS skipped_now, p.pending,
           CASE WHEN r.widened THEN NULL
                ELSE pg_catalog.jsonb_build_object(
                    'scope', r.selection -> 'scope', 'scopeId', r.selection -> 'scopeId', 'runs', r.selection -> 'runs',
                    'resources', r.selection -> 'tables',
                    'agents', CASE WHEN pg_catalog.jsonb_typeof(r.selection -> 'agents') = 'array'
                                   THEN (SELECT pg_catalog.to_jsonb(pg_catalog.array_agg('agent:' || n.name ORDER BY ('agent:' || n.name) COLLATE "C"))
                                           FROM pg_catalog.jsonb_array_elements_text(r.selection -> 'agents') a
                                           JOIN basalt_meta.agent_names n ON n.role::text = a)
                                   ELSE 'null'::jsonb END) END AS selection,
           r.widened, r.rejected_at, r.reject_note
      FROM basalt_meta.reverts r
      -- Inline, not _revert_progress: a view runs functions as its caller.
      LEFT JOIN LATERAL (SELECT count(l.line_no) FILTER (WHERE l.outcome = 'RESTORED')::int AS restored,
                                count(l.line_no) FILTER (WHERE l.outcome = 'SKIPPED')::int AS skipped,
                                count(l.line_no) FILTER (WHERE l.outcome = 'PENDING')::int AS pending
                           FROM basalt_meta.revert_lines l WHERE l.revert_id = r.revert_id) p ON r.batched
     WHERE r.requested_by = session_user;

REVOKE ALL ON FUNCTION basalt_meta._revert_select_internal(jsonb), basalt_meta._revert_select_text(jsonb) FROM PUBLIC;
