-- Reverts: the scope descriptor, the plan built from the ledger chains, the
-- trial run, prepare, sign and apply (in one call or in batches), and
-- rescope, reset and reject.

-- The row with primary key p_key in table p_table, as jsonb, and its
-- version (xmin), or NULLs. p_lock takes a row lock (apply).
--
-- Pinned to the session settings guard_row pins, as _revert_write: through
-- the engine and basalt revert the transaction is pinned already
-- (PinSession), but a person calling preview_revert, prepare_revert or
-- apply_revert by hand in another session would otherwise get the row in
-- that session's form and every line skipped CHANGED_AFTER. Restate the
-- SET clauses in any CREATE OR REPLACE; TestGuardPinsTheSessionSettings
-- checks it.
CREATE FUNCTION basalt_meta._revert_fetch(p_table oid, p_key jsonb, p_lock boolean, OUT row_now jsonb, OUT row_xmin text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
    SET TimeZone = 'UTC'
    SET DateStyle = 'ISO, MDY'
    SET IntervalStyle = 'postgres'
    SET extra_float_digits = 1
    SET lc_monetary = 'C'
    SET bytea_output = 'hex' AS $$
DECLARE
    v_tbl   text := p_table::regclass::text;
    v_tcols text;
    v_rcols text;
BEGIN
    SELECT string_agg(format('t.%I', k), ', ' ORDER BY n), string_agg(format('r.%I', k), ', ' ORDER BY n)
      INTO v_tcols, v_rcols
      FROM basalt_meta.guarded_tables g CROSS JOIN LATERAL unnest(g.pk_cols) WITH ORDINALITY u(k, n)
     WHERE g.table_oid = p_table::regclass;
    -- Dynamic SQL on a validated table (regclass) and quoted key columns.
    EXECUTE format('SELECT to_jsonb(t), t.xmin::text FROM %s t WHERE (%s) = (SELECT %s FROM jsonb_populate_record(NULL::%s, $1) r)%s',
                   v_tbl, v_tcols, v_rcols, v_tbl, CASE WHEN p_lock THEN ' FOR UPDATE OF t' ELSE '' END)
       INTO row_now, row_xmin USING p_key;
END $$;

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
        it.conflict := 'ROW_GONE';
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

CREATE FUNCTION basalt_meta._revert_running() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM basalt_meta.revert_running r WHERE r.tx = pg_current_xact_id_if_assigned())
$$;

-- A row written by a revert: it must be the one row the revert is writing
-- now, named in basalt.revert_target by _revert_write just before the
-- write (no cascade, no app trigger reaching another row). The target is a
-- transaction-local setting rather than an update of the revert_running
-- row: thousands of updates of one row in one transaction made every
-- lookup walk their versions. Only revert_running, which only the revert
-- functions write, says a revert is running; the setting only narrows
-- which row it may write.
CREATE OR REPLACE FUNCTION basalt_meta._guard_revert_row(
    p_table regclass, p_op text, p_depth int, p_old jsonb, p_new jsonb, p_old_xmin xid, p_new_xmin xid
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
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

-- One inverse write, in its own subtransaction, naming its row in
-- basalt.revert_target. Returns NULL when it landed, else the SQLSTATE that
-- stopped it (BS098: the row was not there). An UPDATE writes only the
-- columns that differ. It parses the stored image back with
-- jsonb_populate_record, so it pins the session settings guard_row pins
-- (see _revert_fetch).
CREATE OR REPLACE FUNCTION basalt_meta._revert_write(it basalt_meta.revert_item) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
    SET TimeZone = 'UTC'
    SET DateStyle = 'ISO, MDY'
    SET IntervalStyle = 'postgres'
    SET extra_float_digits = 1
    SET lc_monetary = 'C'
    SET bytea_output = 'hex' AS $$
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

CREATE FUNCTION basalt_meta._revert_invalid(p_detail text) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'REVERT_INVALID', DETAIL = p_detail;
END $$;

-- Any relay (basalt revert, with the agent credential): verify the
-- person's assertion over a prepared revert and run it in the same call,
-- so there is no signed-but-unapplied revert to replay; for a batched plan,
-- record the signature only (_revert_sign). The revert row is locked before
-- any check, so a rescope and a signature cannot interleave. The binding
-- must carry the stored selection as its select, and the lines are
-- recomputed from that selection, never from the binding. applied_at reads
-- the wall clock.
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
    IF (r.binding_text::jsonb -> 'select') IS DISTINCT FROM r.selection THEN
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
               'table', l -> 'table', 'key', l -> 'key', 'rowHash', l -> 'rowHash',
               'conflict', l -> 'conflict', 'sqlState', l -> 'sqlState')) ORDER BY n), '[]'::jsonb)
      INTO v_skipped
      FROM unnest(v_lines) WITH ORDINALITY u(t, n) CROSS JOIN LATERAL (SELECT u.t::jsonb AS l) j
     WHERE l ->> 'action' = 'SKIP';
    PERFORM basalt_meta._append(session_user, v_change, 'REVERTED', NULL, 'REVERT', NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', r.revert_id, 'scope', r.scope, 'scopeId', r.scope_id, 'select', r.selection,
                           'intent', r.intent, 'credentialId', encode(p_credential_id, 'hex'),
                           'binding', encode(r.binding, 'hex'), 'rows', v_rows, 'skipped', v_skipped));
    RETURN jsonb_build_object('changeId', v_change, 'rows', v_rows, 'skipped', cardinality(v_lines) - v_rows);
END $$;

-- Whether p_role may see a line's values (decision N12-8): it can SELECT
-- the table, and where RLS filters it, only its own RESTORE lines: the
-- values the role wrote and replaced, never a row someone else changed,
-- a cascaded row or another agent's row, which its policies may hide.
CREATE FUNCTION basalt_meta._line_visible(it basalt_meta.revert_item, p_role name) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce(has_table_privilege(p_role, it.table_oid, 'SELECT'), false)
       AND (NOT basalt_meta._rls_applies(p_role, it.table_oid)
            OR (it.conflict IS NULL AND NOT it.cascaded
                AND NOT EXISTS (SELECT 1 FROM basalt_meta.changes c
                                 WHERE c.change_id = ANY (it.change_ids) AND c.agent <> p_role)))
$$;

-- One revert line (CONTRACT.md, Revert), redacted unless _line_visible.
CREATE OR REPLACE FUNCTION basalt_meta._revert_line(it basalt_meta.revert_item, p_role name) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT CASE WHEN basalt_meta._line_visible(it, p_role)
        THEN jsonb_build_object('op', it.op, 'key', it.key, 'now', it.now, 'set', it.set, 'table', it.table_name,
                                'action', CASE WHEN it.conflict IS NULL THEN 'RESTORE' ELSE 'SKIP' END,
                                'cascaded', it.cascaded, 'conflict', it.conflict, 'sqlState', it.sql_state,
                                'changeIds', to_jsonb(it.change_ids))::text
        ELSE jsonb_build_object('op', it.op, 'table', it.table_name,
                                'action', CASE WHEN it.conflict IS NULL THEN 'RESTORE' ELSE 'SKIP' END,
                                'rowHash', encode(sha256(convert_to(jsonb_build_array(it.key, it.now, it.set)::text, 'UTF8')), 'hex'),
                                'cascaded', it.cascaded, 'conflict', it.conflict, 'redacted', true,
                                'changeIds', to_jsonb(it.change_ids))::text
    END
$$;

-- The lines of items in COLLATE "C" order.
CREATE FUNCTION basalt_meta._revert_text(p_items basalt_meta.revert_item[], p_role name) RETURNS text[]
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce(array_agg(s.line ORDER BY s.line COLLATE "C"), '{}'::text[])
      FROM (SELECT basalt_meta._revert_line(x, p_role) AS line FROM unnest(p_items) x) s
$$;

-- A new chain at ledger row l.
CREATE FUNCTION basalt_meta._revert_chain_start(l basalt_meta.ledger) RETURNS basalt_meta.revert_chain
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT ROW(l.table_oid, l.table_name, l.seq, l.seq, l.op, l.op, l.row_key, l.row_key, l.old_row, NULL,
               NULL, coalesce((l.detail ->> 'cascaded')::boolean, false), false, false, '{}'::uuid[])::basalt_meta.revert_chain
$$;

-- Chain c continued by ledger row l: broken when someone wrote the row
-- between two in-scope changes.
CREATE FUNCTION basalt_meta._revert_chain_next(c basalt_meta.revert_chain, l basalt_meta.ledger) RETURNS basalt_meta.revert_chain
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF (l.op = 'INSERT' AND c.last_op <> 'DELETE')
       OR (l.op <> 'INSERT' AND (l.detail ->> 'xmin') IS DISTINCT FROM c.new_xmin) THEN
        c.broken := true;
    END IF;
    RETURN c;
END $$;

-- Chain c after ledger row l: what the scope left and which changes wrote it.
CREATE FUNCTION basalt_meta._revert_chain_step(c basalt_meta.revert_chain, l basalt_meta.ledger) RETURNS basalt_meta.revert_chain
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    c.last_seq := l.seq;
    c.last_op := l.op;
    c.new_row := l.new_row;
    c.new_xmin := l.detail ->> 'newXmin';
    c.pruned := c.pruned OR l.values_pruned;
    IF NOT l.change_id = ANY (c.change_ids) THEN
        c.change_ids := c.change_ids || l.change_id;
    END IF;
    RETURN c;
END $$;

-- The latest ledger row of a row after p_after, at either of its keys,
-- for ALREADY_REVERTED. One index lookup per key (ledger_table_key): a
-- plain ORDER BY seq DESC LIMIT 1 scans the ledger backwards, which made
-- planning a large revert quadratic.
CREATE FUNCTION basalt_meta._revert_last(p_table oid, p_keys jsonb[], p_after bigint) RETURNS basalt_meta.ledger
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT x.* FROM basalt_meta.ledger x
     WHERE x.seq = (SELECT max(s.seq) FROM unnest(p_keys) k
                     CROSS JOIN LATERAL (SELECT max(y.seq) AS seq FROM basalt_meta.ledger y
                                          WHERE y.kind = 'ROW_CHANGE' AND y.table_oid = p_table AND y.row_key = k
                                            AND y.seq > p_after) s)
$$;

-- The items of a trial run that always rolls back: conflicts found on
-- trial and the step of every write that landed.
CREATE FUNCTION basalt_meta._revert_trial_items(p_items basalt_meta.revert_item[]) RETURNS basalt_meta.revert_item[]
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
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

-- The lines of a revert after a trial run that always rolls back.
CREATE OR REPLACE FUNCTION basalt_meta._revert_trial(p_items basalt_meta.revert_item[], p_role name) RETURNS text[]
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT basalt_meta._revert_text(basalt_meta._revert_trial_items(p_items), p_role)
$$;

-- The skipped lines of a plan as the preparing role saw them, for ledger
-- details: table, key or row hash, reason; no values.
CREATE FUNCTION basalt_meta._revert_skips(p_revert uuid, p_lines int[]) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
               'line', l.line_no, 'table', l.line::jsonb -> 'table', 'key', l.line::jsonb -> 'key',
               'rowHash', l.line::jsonb -> 'rowHash', 'conflict', l.conflict, 'sqlState', l.sql_state))
             ORDER BY l.line_no), '[]'::jsonb)
      FROM basalt_meta.revert_lines l
     WHERE l.revert_id = p_revert AND l.outcome = 'SKIPPED' AND (p_lines IS NULL OR l.line_no = ANY (p_lines))
$$;

-- A batched plan's totals: lines restored, skipped and pending.
CREATE FUNCTION basalt_meta._revert_progress(p_revert uuid, OUT restored int, OUT skipped int, OUT pending int)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT count(l.line_no) FILTER (WHERE l.outcome = 'RESTORED')::int,
           count(l.line_no) FILTER (WHERE l.outcome = 'SKIPPED')::int,
           count(l.line_no) FILTER (WHERE l.outcome = 'PENDING')::int
      FROM basalt_meta.revert_lines l WHERE l.revert_id = p_revert
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
       SET outcome = 'SKIPPED', batch = 0, conflict = l.line::jsonb ->> 'conflict', sql_state = l.line::jsonb ->> 'sqlState'
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

-- One line of a signed plan re-checked with its row locked (decision
-- N12-5): the item recomputed from the stored chain, skipped as
-- CHANGED_AFTER when it no longer matches the signed line.
CREATE FUNCTION basalt_meta._revert_recheck(l basalt_meta.revert_lines, p_role name) RETURNS basalt_meta.revert_item
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    it basalt_meta.revert_item := basalt_meta._revert_item(l.chain, true);
BEGIN
    IF it.conflict IS NULL AND basalt_meta._revert_line(it, p_role) IS DISTINCT FROM l.line THEN
        it.conflict := 'CHANGED_AFTER';
    END IF;
    RETURN it;
END $$;

-- The last batch of a plan: the plan is applied (applied_at reads the wall
-- clock), and each covered change is REVERTED when every line naming it was
-- restored and no table filter left one of its rows out (changes with no
-- line count as restored).
CREATE OR REPLACE FUNCTION basalt_meta._revert_finish(r basalt_meta.reverts, p_batches int) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_progress record;
BEGIN
    SELECT * INTO v_progress FROM basalt_meta._revert_progress(r.revert_id);
    UPDATE basalt_meta.reverts x SET applied_at = clock_timestamp() WHERE x.revert_id = r.revert_id;
    WITH per AS (
        SELECT u.cid, bool_and(l.outcome = 'RESTORED') AS all_restored, bool_or(l.outcome = 'RESTORED') AS any_restored
          FROM basalt_meta.revert_lines l CROSS JOIN LATERAL unnest((l.chain).change_ids) u(cid)
         WHERE l.revert_id = r.revert_id
         GROUP BY u.cid
    ), covered AS (
        SELECT c.cid, p.all_restored, p.any_restored FROM unnest(r.covered) c(cid) LEFT JOIN per p ON p.cid = c.cid
    )
    UPDATE basalt_meta.changes c
       SET reverted_by = CASE WHEN r.change_id = ANY (coalesce(c.reverted_by, '{}'::uuid[])) THEN c.reverted_by
                              ELSE coalesce(c.reverted_by, '{}'::uuid[]) || r.change_id END,
           status = CASE WHEN coalesce(v.all_restored, true) AND basalt_meta._revert_whole(r.selection, c.change_id)
                         THEN 'REVERTED' ELSE c.status END
      FROM covered v
     WHERE c.change_id = v.cid AND (v.any_restored OR v.all_restored IS NULL);
    PERFORM basalt_meta._append(session_user, r.change_id, 'REVERTED', NULL, 'REVERT', NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', r.revert_id, 'scope', r.scope, 'scopeId', r.scope_id, 'intent', r.intent,
                           'rows', v_progress.restored, 'skipped', v_progress.skipped, 'batches', p_batches));
END $$;

-- The role that prepared a signed batched plan: apply up to 200 of its
-- pending lines, within 24 hours of the signature.
CREATE OR REPLACE FUNCTION basalt_meta.apply_revert_batch(p_revert_id uuid, p_lines int[]) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_max_batch constant int := 200;
    r          basalt_meta.reverts;
    v_batch    int;
    v_bad      int;
    v_done     int;
    v_items    basalt_meta.revert_item[];
    v_rows     int;
    v_progress record;
BEGIN
    PERFORM basalt_meta._require_agent();
    SELECT * INTO r FROM basalt_meta.reverts x
     WHERE x.revert_id = p_revert_id AND x.requested_by = session_user FOR UPDATE;
    IF NOT FOUND THEN
        PERFORM basalt_meta._revert_invalid('no such revert');
    END IF;
    IF NOT r.batched THEN
        PERFORM basalt_meta._revert_invalid(format('revert %s is applied in one call by basalt revert, not in batches', r.revert_id));
    END IF;
    IF r.signed_at IS NULL THEN
        PERFORM basalt_meta._revert_invalid('the person has not signed this revert yet (basalt revert)');
    END IF;
    IF r.applied_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_invalid('revert already applied: no line is pending');
    END IF;
    IF r.apply_by <= clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'REVERT_EXPIRED',
            DETAIL = format('signed revert %s had to be applied by %s; prepare it again', r.revert_id, r.apply_by);
    END IF;
    IF coalesce(cardinality(p_lines), 0) NOT BETWEEN 1 AND c_max_batch THEN
        PERFORM basalt_meta._revert_invalid(format('a batch has 1 to %s lines', c_max_batch));
    END IF;
    SELECT n INTO v_bad FROM unnest(p_lines) n GROUP BY n HAVING count(n) > 1 ORDER BY n LIMIT 1;
    IF FOUND THEN
        PERFORM basalt_meta._revert_invalid(format('the batch names line %s twice', v_bad));
    END IF;
    SELECT n INTO v_bad FROM unnest(p_lines) n
     WHERE NOT EXISTS (SELECT 1 FROM basalt_meta.revert_lines l WHERE l.revert_id = r.revert_id AND l.line_no = n)
     ORDER BY n LIMIT 1;
    IF FOUND THEN
        PERFORM basalt_meta._revert_invalid(format('line %s is not in the plan', coalesce(v_bad::text, 'NULL')));
    END IF;
    SELECT l.line_no, l.batch INTO v_bad, v_done FROM basalt_meta.revert_lines l
     WHERE l.revert_id = r.revert_id AND l.line_no = ANY (p_lines) AND l.outcome <> 'PENDING'
     ORDER BY l.line_no LIMIT 1;
    IF FOUND THEN
        PERFORM basalt_meta._revert_invalid(format('line %s was already applied in batch %s', v_bad, v_done));
    END IF;

    v_batch := r.batches + 1;
    PERFORM set_config('lock_timeout', '5s', true);
    INSERT INTO basalt_meta.revert_running (tx, agent, change_id) VALUES (pg_current_xact_id(), session_user, r.change_id);
    v_items := basalt_meta._revert_execute(ARRAY(
        SELECT basalt_meta._revert_recheck(l, r.requested_by) FROM basalt_meta.revert_lines l
         WHERE l.revert_id = r.revert_id AND l.line_no = ANY (p_lines) ORDER BY l.line_no));
    DELETE FROM basalt_meta.revert_running x WHERE x.tx = pg_current_xact_id();

    UPDATE basalt_meta.revert_lines l
       SET outcome = CASE WHEN x.conflict IS NULL THEN 'RESTORED' ELSE 'SKIPPED' END,
           conflict = x.conflict, sql_state = x.sql_state, batch = v_batch
      FROM unnest(v_items) x
     WHERE l.revert_id = r.revert_id AND l.line_no = ANY (p_lines) AND (l.chain).first_seq = x.first_seq;
    SELECT count(x.table_oid)::int INTO v_rows FROM unnest(v_items) x WHERE x.conflict IS NULL;
    UPDATE basalt_meta.changes c SET rows = c.rows + v_rows WHERE c.change_id = r.change_id;
    UPDATE basalt_meta.changes c SET reverted_by = coalesce(c.reverted_by, '{}'::uuid[]) || r.change_id
     WHERE c.change_id IN (SELECT DISTINCT u.cid FROM unnest(v_items) x CROSS JOIN LATERAL unnest(x.change_ids) u(cid)
                            WHERE x.conflict IS NULL)
       AND NOT (r.change_id = ANY (coalesce(c.reverted_by, '{}'::uuid[])));
    UPDATE basalt_meta.reverts x SET batches = v_batch WHERE x.revert_id = r.revert_id;
    SELECT * INTO v_progress FROM basalt_meta._revert_progress(r.revert_id);
    PERFORM basalt_meta._append(session_user, r.change_id, 'REVERT_BATCH', NULL, 'REVERT', NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', r.revert_id, 'batch', v_batch,
                           'lines', (SELECT to_jsonb(array_agg(n ORDER BY n)) FROM unnest(p_lines) n),
                           'rows', v_rows, 'skipped', basalt_meta._revert_skips(r.revert_id, p_lines),
                           'pending', v_progress.pending));
    IF v_progress.pending = 0 THEN
        PERFORM basalt_meta._revert_finish(r, v_batch);
    END IF;
    RETURN jsonb_build_object(
        'revertId', r.revert_id, 'batch', v_batch,
        'status', CASE WHEN v_progress.pending = 0 THEN 'APPLIED' ELSE 'APPLYING' END,
        'restored', v_progress.restored, 'skipped', v_progress.skipped, 'pending', v_progress.pending,
        'items', (SELECT jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
                             'line', l.line_no, 'outcome', l.outcome, 'conflict', l.conflict, 'sqlState', l.sql_state))
                           ORDER BY u.n)
                    FROM unnest(p_lines) WITH ORDINALITY u(no, n)
                    JOIN basalt_meta.revert_lines l ON l.revert_id = r.revert_id AND l.line_no = u.no));
END $$;

-- The lines a batched plan's link carries: up to half of p_max SKIP lines
-- and up to half RESTORE lines; when one kind has fewer, the other fills
-- the rest, at most p_max in all. SKIP lines first, each kind in signed
-- order (decision RSS-1). Must match revert.Sample and revert.SampleCounts.
CREATE OR REPLACE FUNCTION basalt_meta._revert_sample(p_lines text[], p_max int) RETURNS text[]
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
    WITH l AS (
        SELECT u.l, u.n, (u.l::jsonb ->> 'action') = 'RESTORE' AS restore,
               row_number() OVER (PARTITION BY (u.l::jsonb ->> 'action') = 'RESTORE' ORDER BY u.n) AS k
          FROM unnest(p_lines) WITH ORDINALITY u(l, n)
    ), c AS (
        SELECT count(l.n) FILTER (WHERE NOT l.restore)::int AS skips,
               count(l.n) FILTER (WHERE l.restore)::int AS restores
          FROM l
    ), t AS (
        SELECT least(c.skips, greatest(p_max / 2, p_max - c.restores)) AS skips, c.restores FROM c
    )
    SELECT coalesce(array_agg(l.l ORDER BY l.restore, l.n), '{}')
      FROM l, t
     WHERE (NOT l.restore AND l.k <= t.skips)
        OR (l.restore AND l.k <= least(t.restores, p_max - t.skips))
$$;

-- A scope descriptor refused (BS011): DETAIL is the reason the engine maps
-- (SHAPE, STORE_RESERVED, FILTER_CAP, NOT_OWN_CHANGE, NOT_OWN_RUN,
-- NOT_OWN_TASK, FILTER), HINT what to change.
CREATE OR REPLACE FUNCTION basalt_meta._scope_refused(p_detail text, p_hint text) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'BS011', MESSAGE = 'SCOPE_REFUSED', DETAIL = p_detail, HINT = p_hint;
END $$;

-- A JSON list of the descriptor (agents, runs or tables) sorted by its text
-- COLLATE "C" and deduplicated, or JSON null.
CREATE OR REPLACE FUNCTION basalt_meta._revert_select_list(p_list jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT CASE WHEN jsonb_typeof(p_list) = 'array'
                THEN (SELECT to_jsonb(array_agg(s.e ORDER BY s.e COLLATE "C"))
                        FROM (SELECT DISTINCT e FROM jsonb_array_elements_text(p_list) e) s)
                ELSE 'null'::jsonb END
$$;

-- The descriptor checked for shape and normalized (CONTRACT.md, The scope
-- descriptor): every key present, lists sorted and deduplicated, null for
-- all, ids in canonical form. Reads nothing but its argument, so a refusal
-- here says nothing about any data: SHAPE, STORE_RESERVED (RS-4) or
-- FILTER_CAP (at most 20 runs and 20 tables).
CREATE OR REPLACE FUNCTION basalt_meta._revert_select_norm(p jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_max_filter constant int  := 20; -- runs and tables in a descriptor (owner, Q10)
    c_max_name   constant int  := 63; -- NAMEDATALEN - 1
    c_uuid       constant text := '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$';
    c_table      constant text := '^[^.\s]+\.[^.\s]+$';
    v_key  text;
    v_list text;
BEGIN
    IF jsonb_typeof(p) IS DISTINCT FROM 'object' THEN
        PERFORM basalt_meta._scope_refused('SHAPE', 'the scope descriptor is a JSON object');
    END IF;
    IF p ? 'store' THEN
        PERFORM basalt_meta._scope_refused('STORE_RESERVED', 'store is reserved for multi-database work; leave it out');
    END IF;
    SELECT k INTO v_key FROM jsonb_object_keys(p) k
     WHERE k NOT IN ('scope', 'scopeId', 'agents', 'runs', 'tables') ORDER BY k LIMIT 1;
    IF FOUND THEN
        PERFORM basalt_meta._scope_refused('SHAPE', 'the scope descriptor has only scope, scopeId, agents, runs and tables');
    END IF;
    FOREACH v_key IN ARRAY ARRAY['scope', 'scopeId', 'agents', 'runs', 'tables'] LOOP
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
    FOREACH v_list IN ARRAY ARRAY['agents', 'runs', 'tables'] LOOP
        CONTINUE WHEN jsonb_typeof(p -> v_list) = 'null';
        IF jsonb_typeof(p -> v_list) IS DISTINCT FROM 'array' OR jsonb_array_length(p -> v_list) = 0 THEN
            PERFORM basalt_meta._scope_refused('SHAPE', format('%s is null (all) or a list of at least one', v_list));
        END IF;
        IF v_list <> 'agents' AND jsonb_array_length(p -> v_list) > c_max_filter THEN
            PERFORM basalt_meta._scope_refused('FILTER_CAP', format('%s has at most %s entries; leave it null for all', v_list, c_max_filter));
        END IF;
        IF EXISTS (SELECT 1 FROM jsonb_array_elements(p -> v_list) e
                    WHERE jsonb_typeof(e) IS DISTINCT FROM 'string'
                       OR CASE v_list WHEN 'agents' THEN length(e #>> '{}') NOT BETWEEN 1 AND c_max_name
                                      WHEN 'runs' THEN (e #>> '{}') !~ c_uuid
                                      ELSE (e #>> '{}') !~ c_table END) THEN
            PERFORM basalt_meta._scope_refused('SHAPE', CASE v_list WHEN 'agents' THEN 'agents are role names'
                                                                     WHEN 'runs' THEN 'runs are run ids'
                                                                     ELSE 'tables are schema.table names' END);
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
                              (SELECT jsonb_agg(((e)::uuid)::text) FROM jsonb_array_elements_text(p -> 'runs') e))
                     ELSE 'null'::jsonb END,
        'tables', basalt_meta._revert_select_list(p -> 'tables'));
END $$;

-- The changes a descriptor covers: applied (or already reverted) writes,
-- reverts included, of the scope, by its agents (every agent when null), in
-- its runs (every run when null). A TASK of listed agents is looked up by
-- (task_id, agent) in its own statement, so the changes_task_agent index
-- serves it.
CREATE OR REPLACE FUNCTION basalt_meta._revert_scope(p_sel jsonb) RETURNS TABLE (change_id uuid, agent name)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_id     uuid := (p_sel ->> 'scopeId')::uuid;
    v_agents name[] := basalt_meta._revert_select_agents(p_sel);
BEGIN
    IF p_sel ->> 'scope' = 'TASK' AND v_agents IS NOT NULL THEN
        RETURN QUERY SELECT c.change_id, c.agent FROM basalt_meta.changes c
         WHERE c.task_id = v_id AND c.agent = ANY (v_agents)
           AND c.mode = 'APPLY' AND c.status IN ('APPLIED', 'REVERTED')
           AND c.op IN ('INSERT', 'UPDATE', 'DELETE', 'REVERT')
           AND (jsonb_typeof(p_sel -> 'runs') IS DISTINCT FROM 'array' OR (p_sel -> 'runs') ? c.run_id::text);
        RETURN;
    END IF;
    RETURN QUERY SELECT c.change_id, c.agent FROM basalt_meta.changes c
     WHERE c.mode = 'APPLY' AND c.status IN ('APPLIED', 'REVERTED')
       AND c.op IN ('INSERT', 'UPDATE', 'DELETE', 'REVERT')
       AND CASE p_sel ->> 'scope' WHEN 'CHANGE' THEN c.change_id = v_id
                                  WHEN 'RUN' THEN c.run_id = v_id
                                  ELSE c.task_id = v_id END
       AND (v_agents IS NULL OR c.agent = ANY (v_agents))
       AND (jsonb_typeof(p_sel -> 'runs') IS DISTINCT FROM 'array' OR (p_sel -> 'runs') ? c.run_id::text);
END $$;

-- The ledger rows a descriptor covers: the row changes of its changes, on
-- its tables (every table when null). A table filter filters rows, not
-- changes: a change that wrote two tables can be half selected.
CREATE OR REPLACE FUNCTION basalt_meta._revert_rows(p_sel jsonb) RETURNS SETOF basalt_meta.ledger
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT x.* FROM basalt_meta.ledger x
     WHERE x.kind = 'ROW_CHANGE'
       AND x.change_id IN (SELECT s.change_id FROM basalt_meta._revert_scope(p_sel) s)
       AND (jsonb_typeof(p_sel -> 'tables') IS DISTINCT FROM 'array' OR (p_sel -> 'tables') ? x.table_name)
$$;

-- The changes a revert of the descriptor covers: those of _revert_scope
-- with a row change on its tables (all of them without a table filter).
-- They get the revert in reverted_by.
CREATE OR REPLACE FUNCTION basalt_meta._revert_covered(p_sel jsonb) RETURNS SETOF uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT s.change_id FROM basalt_meta._revert_scope(p_sel) s
     WHERE jsonb_typeof(p_sel -> 'tables') IS DISTINCT FROM 'array'
        OR EXISTS (SELECT 1 FROM basalt_meta.ledger x
                    WHERE x.kind = 'ROW_CHANGE' AND x.change_id = s.change_id AND (p_sel -> 'tables') ? x.table_name)
$$;

-- True when a revert of the descriptor covers every row change of change
-- p_change (no table filter leaves one out), so the change may become
-- REVERTED.
CREATE OR REPLACE FUNCTION basalt_meta._revert_whole(p_sel jsonb, p_change uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT jsonb_typeof(p_sel -> 'tables') IS DISTINCT FROM 'array'
        OR NOT EXISTS (SELECT 1 FROM basalt_meta.ledger x
                        WHERE x.kind = 'ROW_CHANGE' AND x.change_id = p_change
                          AND NOT (p_sel -> 'tables') ? x.table_name)
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
    v_sel     jsonb := basalt_meta._revert_select_norm(p);
    v_refusal text[] := basalt_meta._revert_own_refusal(v_sel, session_user);
BEGIN
    IF v_refusal IS NOT NULL THEN
        PERFORM basalt_meta._scope_refused(v_refusal[1], v_refusal[2]);
    END IF;
    RETURN v_sel;
END $$;

-- The key-following walk over the rows a descriptor covers (_revert_rows),
-- kept for scopes where a row changed its primary key.
CREATE OR REPLACE FUNCTION basalt_meta._revert_chains_walk(p_sel jsonb) RETURNS SETOF basalt_meta.revert_chain
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_chains basalt_meta.revert_chain[] := '{}';
    v_map    jsonb := '{}';
    v_slot   text;
    v_key    jsonb;
    i        int;
    c        basalt_meta.revert_chain;
    l        basalt_meta.ledger;
BEGIN
    FOR l IN SELECT x.* FROM basalt_meta._revert_rows(p_sel) x ORDER BY x.seq LOOP
        v_slot := l.table_oid::text || ':' || l.row_key::text;
        i := (v_map ->> v_slot)::int;
        IF i IS NULL THEN
            c := basalt_meta._revert_chain_start(l);
            v_chains := v_chains || c;
            i := cardinality(v_chains);
        ELSE
            c := basalt_meta._revert_chain_next(v_chains[i], l);
        END IF;
        c := basalt_meta._revert_chain_step(c, l);
        v_key := l.row_key;
        IF l.op <> 'DELETE' AND l.new_row IS NOT NULL THEN
            v_key := basalt_meta._row_key(l.table_oid::regclass, l.new_row);
        END IF;
        c.cur_key := v_key;
        v_chains[i] := c;
        v_map := (v_map - v_slot) || jsonb_build_object(l.table_oid::text || ':' || v_key::text, i);
    END LOOP;
    RETURN QUERY SELECT x.* FROM unnest(v_chains) x;
END $$;

CREATE OR REPLACE FUNCTION basalt_meta._revert_chains(p_sel jsonb) RETURNS SETOF basalt_meta.revert_chain
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c      basalt_meta.revert_chain;
    l      basalt_meta.ledger;
    v_open boolean := false;
BEGIN
    IF EXISTS (SELECT 1 FROM basalt_meta._revert_rows(p_sel) x
                WHERE x.op = 'UPDATE' AND x.new_row IS NOT NULL
                  AND basalt_meta._row_key(x.table_oid::regclass, x.new_row) IS DISTINCT FROM x.row_key) THEN
        RETURN QUERY SELECT * FROM basalt_meta._revert_chains_walk(p_sel);
        RETURN;
    END IF;
    FOR l IN SELECT x.* FROM basalt_meta._revert_rows(p_sel) x ORDER BY x.table_oid, x.row_key, x.seq LOOP
        IF v_open AND c.table_oid = l.table_oid AND c.orig_key = l.row_key THEN
            c := basalt_meta._revert_chain_next(c, l);
        ELSE
            IF v_open THEN
                RETURN NEXT c;
            END IF;
            c := basalt_meta._revert_chain_start(l);
            v_open := true;
        END IF;
        c := basalt_meta._revert_chain_step(c, l);
    END LOOP;
    IF v_open THEN
        RETURN NEXT c;
    END IF;
END $$;

-- The chains that need a line, in ledger order of their first row.
-- NOTHING_TO_REVERT when none, unless p_empty_ok (a task proposal the
-- person may widen).
CREATE OR REPLACE FUNCTION basalt_meta._revert_chain_list(p_sel jsonb, p_empty_ok boolean) RETURNS basalt_meta.revert_chain[]
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_chains basalt_meta.revert_chain[];
BEGIN
    v_chains := ARRAY(SELECT x FROM basalt_meta._revert_chains(p_sel) x
                       WHERE NOT (x.first_op = 'INSERT' AND x.last_op = 'DELETE')
                       ORDER BY x.first_seq);
    IF cardinality(v_chains) = 0 AND NOT p_empty_ok THEN
        RAISE EXCEPTION USING ERRCODE = 'BS009', MESSAGE = 'NOTHING_TO_REVERT',
            DETAIL = format('%s %s changed no rows that a revert could restore', p_sel ->> 'scope', p_sel ->> 'scopeId');
    END IF;
    RETURN v_chains;
END $$;

CREATE OR REPLACE FUNCTION basalt_meta._revert_items(p_sel jsonb, p_lock boolean) RETURNS basalt_meta.revert_item[]
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT ARRAY(SELECT basalt_meta._revert_item(x, p_lock)
                   FROM unnest(basalt_meta._revert_chain_list(p_sel, false)) x)
$$;

-- Lines per agent role among items, RESTORE and SKIP: a line counts for
-- every agent with a change in it. The binding's agentRows.
CREATE OR REPLACE FUNCTION basalt_meta._revert_agent_rows(p_items basalt_meta.revert_item[]) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce(jsonb_object_agg(a.agent, a.n), '{}'::jsonb)
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
        'kind', 'REVERT', 'revertId', p_id, 'database', current_database(), 'select', p_select,
        'widened', basalt_meta._widened(p_select, p_requested_by), 'intent', p_intent, 'rows', p_rows,
        'skipped', p_skipped, 'rowsHash', encode(p_rows_hash, 'hex'),
        'expiresAt', to_char(p_expires AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'requestedBy', p_requested_by)
        || CASE WHEN p_proposed IS DISTINCT FROM p_select THEN jsonb_build_object('proposed', p_proposed)
                ELSE '{}'::jsonb END
        || CASE WHEN basalt_meta._widened(p_select, p_requested_by) THEN jsonb_build_object('agentRows', p_agent_rows)
                ELSE '{}'::jsonb END
        || CASE WHEN p_sample_hash IS NOT NULL
                THEN jsonb_build_object('batched', true, 'sampleHash', encode(p_sample_hash, 'hex'))
                ELSE '{}'::jsonb END)::text
$$;

-- Agent (MCP preview_revert, basalt revert --dry-run): what reverting the
-- agent's own proposal p_select would do, from a trial run that always
-- rolls back. Needs a read-write transaction; it leaves nothing behind.
CREATE OR REPLACE FUNCTION basalt_meta.preview_revert(p_select jsonb) RETURNS SETOF text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_sel jsonb;
BEGIN
    PERFORM basalt_meta._require_agent();
    v_sel := basalt_meta._revert_own_select(p_select);
    RETURN QUERY SELECT u.line
      FROM unnest(basalt_meta._revert_trial(basalt_meta._revert_items(v_sel, false), session_user))
           WITH ORDINALITY u(line, n)
     ORDER BY u.n;
END $$;

-- Agent, as the CLI's relay and for request_revert: store the agent's own
-- proposal p_select for the person to sign. selection = proposed = the
-- normalized descriptor, a fresh rescope nonce, and the binding built from
-- them. A TASK the caller ran in with no line of its own is stored as an
-- empty proposal the person may widen on the page (it cannot be signed as
-- it is); every other scope with nothing to restore is NOTHING_TO_REVERT.
CREATE OR REPLACE FUNCTION basalt_meta.prepare_revert(p_select jsonb, p_intent text)
RETURNS TABLE (revert_id uuid, binding_text text, expires_at timestamptz, lines text[])
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    c_ttl       constant interval := interval '1 hour';
    c_max_lines constant int := 1000; -- one-call revert and lines in a link (M3-9, N12-4, RSS-1)
    v_id        uuid := basalt_meta._uuidv7();
    v_expires   timestamptz := now() + c_ttl;
    v_sel       jsonb;
    v_chains    basalt_meta.revert_chain[];
    v_items     basalt_meta.revert_item[];
    v_lines     text[];
    v_sample    text[];
    v_rows      int;
    v_covered   uuid[];
    v_hash      bytea;
    v_sample_h  bytea;
    v_batched   boolean;
    v_text      text;
BEGIN
    PERFORM basalt_meta._require_agent();
    PERFORM basalt_meta._check_text('intent', p_intent, 2000, true);
    v_sel := basalt_meta._revert_own_select(p_select);
    v_chains := basalt_meta._revert_chain_list(v_sel, v_sel ->> 'scope' = 'TASK');
    v_items := basalt_meta._revert_trial_items(ARRAY(SELECT basalt_meta._revert_item(x, false) FROM unnest(v_chains) x));
    v_lines := basalt_meta._revert_text(v_items, session_user);
    SELECT count(x.table_oid)::int INTO v_rows FROM unnest(v_items) x WHERE x.conflict IS NULL;
    IF v_rows = 0 AND cardinality(v_lines) > 0 THEN
        RAISE EXCEPTION USING ERRCODE = 'BS009', MESSAGE = 'NOTHING_TO_REVERT',
            DETAIL = format('every row of %s %s would be skipped', v_sel ->> 'scope', v_sel ->> 'scopeId');
    END IF;
    SELECT array_agg(s ORDER BY s) INTO v_covered FROM basalt_meta._revert_covered(v_sel) s;
    v_hash := sha256(convert_to(array_to_string(v_lines, E'\n'), 'UTF8'));
    v_batched := cardinality(v_lines) > c_max_lines;
    v_sample := v_lines;
    IF v_batched THEN
        v_sample := basalt_meta._revert_sample(v_lines, c_max_lines);
        v_sample_h := sha256(convert_to(array_to_string(v_sample, E'\n'), 'UTF8'));
    END IF;
    v_text := basalt_meta._revert_binding(v_id, v_sel, v_sel, session_user, p_intent, v_rows,
                                          cardinality(v_lines) - v_rows, v_hash, v_expires, v_sample_h,
                                          basalt_meta._revert_agent_rows(v_items));
    INSERT INTO basalt_meta.reverts (revert_id, selection, proposed, rescope_nonce, requested_by, intent, lines, rows,
                                     skipped, rows_hash, binding_text, binding, expires_at, batched, sample_hash, covered)
    VALUES (v_id, v_sel, v_sel, basalt_meta._revert_nonce(), session_user, p_intent, v_sample, v_rows,
            cardinality(v_lines) - v_rows, v_hash, v_text, sha256(convert_to(v_text, 'UTF8')), v_expires, v_batched,
            v_sample_h, v_covered);
    IF v_batched THEN
        -- Execution order: the writes that landed on trial in the order they
        -- landed, then the lines the trial skipped.
        INSERT INTO basalt_meta.revert_lines (revert_id, line_no, line, chain)
        SELECT v_id, row_number() OVER (ORDER BY it.step NULLS LAST, it.first_seq),
               basalt_meta._revert_line(it, session_user), ch
          FROM unnest(v_items) it JOIN unnest(v_chains) ch ON ch.first_seq = it.first_seq;
    END IF;
    PERFORM basalt_meta._append(session_user, NULL, 'REVERT_PENDING', NULL, NULL, NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', v_id, 'scope', v_sel ->> 'scope', 'scopeId', v_sel ->> 'scopeId',
                           'select', v_sel, 'intent', p_intent, 'rows', v_rows,
                           'skipped', cardinality(v_lines) - v_rows,
                           'rowsHash', encode(v_hash, 'hex'), 'expiresAt', v_expires)
        || CASE WHEN v_batched THEN jsonb_build_object('batched', true) ELSE '{}'::jsonb END);
    revert_id := v_id;
    binding_text := v_text;
    expires_at := v_expires;
    lines := v_sample;
    RETURN NEXT;
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
        RETURN ARRAY['FILTER', 'agents is exactly your own role: an agent proposes only its own work'];
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

-- base64url (no padding) to bytes, NULL when t is not base64url.
CREATE OR REPLACE FUNCTION basalt_meta._b64url_decode(t text) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
    SELECT CASE WHEN t ~ '^[A-Za-z0-9_-]*$' AND length(t) % 4 <> 1
                THEN decode(rpad(translate(t, '-_', '+/'), (length(t) + 3) / 4 * 4, '='), 'base64') END
$$;

-- The one answer to every failed proof or token check of rescope_revert
-- (CONTRACT.md, Rescope, widen and reject, check order step 3): whatever
-- failed, the caller learns nothing about other agents' work.
CREATE OR REPLACE FUNCTION basalt_meta._widen_refused() RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'REVERT_INVALID', DETAIL = 'WIDEN_REFUSED',
        HINT = 'a scope beyond the requesting agent''s own work, and any scope change after the person widened it, needs the person on the revert page';
END $$;

-- The caller's own revert p_revert_id, locked, while its scope may still
-- change: not applied, rejected, signed or expired. Another role's revert
-- reads like one that does not exist.
CREATE OR REPLACE FUNCTION basalt_meta._revert_lock_pending(p_revert_id uuid) RETURNS basalt_meta.reverts
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    r basalt_meta.reverts;
BEGIN
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
        PERFORM basalt_meta._revert_invalid('revert already signed; its scope can no longer change');
    END IF;
    IF r.expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'REVERT_EXPIRED',
            DETAIL = format('revert %s expired at %s; prepare it again', r.revert_id, r.expires_at);
    END IF;
    RETURN r;
END $$;

-- True when p_proof is the person's widen proof for revert r and select
-- p_sel with key p_key: a passkey assertion, checked as submit_approval's
-- (_verify_assertion), over sha256("basalt-rescope.1\n" + revertId + "\n"
-- + base64url(nonce) + "\n" + hex(sha256(key)) + "\n" + select text).
-- Never raises for a bad proof: any error of the check (WHEN OTHERS; a
-- cancel still raises) is a bad proof, so every failure reads the same.
CREATE OR REPLACE FUNCTION basalt_meta._rescope_proven(r basalt_meta.reverts, p_sel jsonb, p_proof jsonb, p_key bytea) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_key_len constant int := 32; -- HKDF-SHA-256 output, CONTRACT.md
    v_challenge bytea;
BEGIN
    IF octet_length(p_key) IS DISTINCT FROM c_key_len OR jsonb_typeof(p_proof) IS DISTINCT FROM 'object' THEN
        RETURN false;
    END IF;
    v_challenge := sha256(convert_to(concat_ws(E'\n', 'basalt-rescope.1', r.revert_id::text,
        basalt_meta._b64url(r.rescope_nonce), encode(sha256(p_key), 'hex'), p_sel::text), 'UTF8'));
    BEGIN
        PERFORM basalt_meta._verify_assertion(v_challenge,
            basalt_meta._b64url_decode(p_proof ->> 'credentialId'),
            basalt_meta._b64url_decode(p_proof ->> 'authenticatorData'),
            basalt_meta._b64url_decode(p_proof ->> 'clientDataJson'),
            basalt_meta._b64url_decode(p_proof ->> 'signature'));
    EXCEPTION WHEN OTHERS THEN
        RETURN false;
    END;
    RETURN true;
END $$;

-- True when the normalized select p_sel lies inside the ceiling: the same
-- scope, and agents, runs and tables each a subset of the ceiling's (any,
-- when the ceiling's is null).
CREATE OR REPLACE FUNCTION basalt_meta._revert_select_within(p_sel jsonb, p_ceiling jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT p_sel ->> 'scope' = p_ceiling ->> 'scope' AND p_sel ->> 'scopeId' = p_ceiling ->> 'scopeId'
       AND NOT EXISTS (SELECT 1 FROM unnest(ARRAY['agents', 'runs', 'tables']) k
                        WHERE jsonb_typeof(p_ceiling -> k) = 'array'
                          AND (jsonb_typeof(p_sel -> k) IS DISTINCT FROM 'array' OR NOT (p_ceiling -> k) @> (p_sel -> k)))
$$;

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
        SELECT format('agent %s has no change in this scope', u.a)
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
-- runs and the tables written. Returned only to a proven or token-bearing
-- rescope_revert call; no view holds it.
CREATE OR REPLACE FUNCTION basalt_meta._revert_catalog(p_sel jsonb) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    WITH s AS (SELECT c.change_id, c.agent, c.run_id FROM basalt_meta._revert_scope(p_sel) x
                 JOIN basalt_meta.changes c ON c.change_id = x.change_id)
    SELECT pg_catalog.jsonb_build_object(
        'agents', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('agent', a.agent, 'changes', a.n) ORDER BY a.agent::text COLLATE "C")
                              FROM (SELECT s.agent, pg_catalog.count(s.change_id)::int AS n FROM s GROUP BY s.agent) a), '[]'::jsonb),
        'runs', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                                     'runId', u.run_id, 'agent', u.agent, 'changes', u.n,
                                     'startedAt', pg_catalog.to_char(r.started_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
                                 ORDER BY u.run_id)
                            FROM (SELECT s.run_id, s.agent, pg_catalog.count(s.change_id)::int AS n FROM s
                                   WHERE s.run_id IS NOT NULL GROUP BY s.run_id, s.agent) u
                            JOIN basalt_meta.runs r ON r.run_id = u.run_id), '[]'::jsonb),
        'tables', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('table', t.table_name, 'rows', t.n) ORDER BY t.table_name COLLATE "C")
                              FROM (SELECT x.table_name, pg_catalog.count(x.seq)::int AS n FROM basalt_meta._revert_rows(p_sel) x
                                     GROUP BY x.table_name) t), '[]'::jsonb),
        -- Each change in the scope to the role that made it, so the page
        -- tags every row of a multi-agent select (Q-11).
        'changeAgents', coalesce((SELECT pg_catalog.jsonb_object_agg(s.change_id::text, s.agent::text) FROM s), '{}'::jsonb))
$$;

-- Rebuild pending revert r for the normalized select p_sel, as
-- prepare_revert builds a new one: the trial run, the lines for the
-- requesting role, totals, rowsHash, a large plan's numbered lines and
-- sample, the binding (with r's proposal) and a fresh one-hour expiry. A
-- TASK with no line is stored empty (the page disables signing); any other
-- scope with nothing to restore is NOTHING_TO_REVERT. Returns the row.
CREATE OR REPLACE FUNCTION basalt_meta._revert_rebuild(r basalt_meta.reverts, p_sel jsonb) RETURNS basalt_meta.reverts
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_ttl       constant interval := interval '1 hour';
    c_max_lines constant int := 1000; -- one-call revert and lines in a link (M3-9, N12-4, RSS-1)
    v_expires   timestamptz := now() + c_ttl;
    v_chains    basalt_meta.revert_chain[];
    v_items     basalt_meta.revert_item[];
    v_lines     text[];
    v_sample    text[];
    v_rows      int;
    v_hash      bytea;
    v_sample_h  bytea;
    v_batched   boolean;
    v_text      text;
    v_out       basalt_meta.reverts;
BEGIN
    v_chains := basalt_meta._revert_chain_list(p_sel, p_sel ->> 'scope' = 'TASK');
    v_items := basalt_meta._revert_trial_items(ARRAY(SELECT basalt_meta._revert_item(x, false) FROM unnest(v_chains) x));
    v_lines := basalt_meta._revert_text(v_items, r.requested_by);
    SELECT count(x.table_oid)::int INTO v_rows FROM unnest(v_items) x WHERE x.conflict IS NULL;
    IF v_rows = 0 AND cardinality(v_lines) > 0 THEN
        RAISE EXCEPTION USING ERRCODE = 'BS009', MESSAGE = 'NOTHING_TO_REVERT',
            DETAIL = format('every row of %s %s would be skipped', p_sel ->> 'scope', p_sel ->> 'scopeId');
    END IF;
    v_hash := sha256(convert_to(array_to_string(v_lines, E'\n'), 'UTF8'));
    v_batched := cardinality(v_lines) > c_max_lines;
    v_sample := v_lines;
    IF v_batched THEN
        v_sample := basalt_meta._revert_sample(v_lines, c_max_lines);
        v_sample_h := sha256(convert_to(array_to_string(v_sample, E'\n'), 'UTF8'));
    END IF;
    v_text := basalt_meta._revert_binding(r.revert_id, p_sel, r.proposed, r.requested_by, r.intent, v_rows,
                                          cardinality(v_lines) - v_rows, v_hash, v_expires, v_sample_h,
                                          basalt_meta._revert_agent_rows(v_items));
    DELETE FROM basalt_meta.revert_lines l WHERE l.revert_id = r.revert_id;
    UPDATE basalt_meta.reverts x
       SET selection = p_sel, lines = v_sample, rows = v_rows, skipped = cardinality(v_lines) - v_rows,
           rows_hash = v_hash, binding_text = v_text, binding = sha256(convert_to(v_text, 'UTF8')),
           expires_at = v_expires, batched = v_batched, sample_hash = v_sample_h,
           covered = (SELECT array_agg(s ORDER BY s) FROM basalt_meta._revert_covered(p_sel) s)
     WHERE x.revert_id = r.revert_id
    RETURNING x.* INTO v_out;
    IF v_batched THEN
        -- Execution order, as prepare_revert: the writes that landed on
        -- trial in the order they landed, then the lines the trial skipped.
        INSERT INTO basalt_meta.revert_lines (revert_id, line_no, line, chain)
        SELECT r.revert_id, row_number() OVER (ORDER BY it.step NULLS LAST, it.first_seq),
               basalt_meta._revert_line(it, r.requested_by), ch
          FROM unnest(v_items) it JOIN unnest(v_chains) ch ON ch.first_seq = it.first_seq;
    END IF;
    RETURN v_out;
END $$;

-- What rescope_revert and reset_revert return for revert r: the request
-- the page checks, and the nonce a widen proof signs next.
CREATE OR REPLACE FUNCTION basalt_meta._revert_rescoped(r basalt_meta.reverts) RETURNS jsonb
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT jsonb_build_object('revertId', r.revert_id, 'binding', r.binding_text, 'expiresAt', r.expires_at,
                              'lines', to_jsonb(coalesce(r.lines, '{}'::text[])),
                              'rescopeNonce', basalt_meta._b64url(r.rescope_nonce))
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
    v_sel   jsonb;
    v_via   text;
    v_token bytea;
    v_out   basalt_meta.reverts;
BEGIN
    PERFORM basalt_meta._require_agent();
    v_sel := basalt_meta._revert_select_norm(p_select);
    r := basalt_meta._revert_lock_pending(p_revert_id);
    CASE
    WHEN p_proof IS NOT NULL THEN
        IF NOT basalt_meta._rescope_proven(r, v_sel, p_proof, p_rescope_key) THEN
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

-- Agent, for its reissueLink on a widened revert (owner, Q8): put the
-- caller's own pending revert back to its proposal. The lines are rebuilt,
-- the ceiling and scope token cleared, a new nonce set, and REVERT_RESET
-- appended with the select it dropped. It only ever narrows to the agent's
-- own work, so it needs no token.
CREATE OR REPLACE FUNCTION basalt_meta.reset_revert(p_revert_id uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    r     basalt_meta.reverts;
    v_out basalt_meta.reverts;
BEGIN
    PERFORM basalt_meta._require_agent();
    r := basalt_meta._revert_lock_pending(p_revert_id);
    PERFORM basalt_meta._revert_rebuild(r, r.proposed);
    UPDATE basalt_meta.reverts x
       SET ceiling = NULL, scope_token_hash = NULL, rescope_nonce = basalt_meta._revert_nonce()
     WHERE x.revert_id = r.revert_id
    RETURNING x.* INTO v_out;
    PERFORM basalt_meta._append(session_user, NULL, 'REVERT_RESET', NULL, NULL, NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', r.revert_id, 'droppedSelect', r.selection,
                           'oldRowsHash', encode(r.rows_hash, 'hex'), 'rowsHash', encode(v_out.rows_hash, 'hex')));
    RETURN basalt_meta._revert_rescoped(v_out);
END $$;

CREATE OR REPLACE FUNCTION basalt_meta.revert_nonce(p_revert_id uuid) RETURNS bytea
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_nonce bytea;
BEGIN
    SELECT r.rescope_nonce INTO v_nonce FROM basalt_meta.reverts r
     WHERE r.revert_id = p_revert_id AND r.requested_by = session_user;
    IF NOT FOUND THEN
        PERFORM basalt_meta._revert_invalid('no such revert');
    END IF;
    RETURN v_nonce;
END $$;

-- Agent, for the engine's reject route: mark the caller's own pending,
-- unsigned, unexpired revert REJECTED. In this order, stopping at the first
-- failure:
--   1. the note, from p_note alone: at most 500 characters (BS008);
--   2. the revert, locked: another role's revert reads like an unknown id,
--      and an applied, signed, rejected or expired one is refused
--      (_revert_lock_pending);
--   3. the scope token: required once the revert has a ceiling, refused
--      on a revert never widened; every failure is REVERT_INVALID
--      WIDEN_REFUSED.
-- Then REJECTED is set (rejected_at reads the wall clock after the revert
-- is locked) and REVERT_REJECTED appended with the note and the path
-- (via). The token is never recorded.
CREATE OR REPLACE FUNCTION basalt_meta.reject_revert(p_revert_id uuid, p_note text, p_token bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    r      basalt_meta.reverts;
    v_note text := nullif(p_note, '');
    v_via  text := 'LINK_OR_AGENT';
    v_at   timestamptz;
BEGIN
    PERFORM basalt_meta._require_agent();
    IF char_length(v_note) > 500 THEN
        RAISE EXCEPTION USING ERRCODE = 'BS008', MESSAGE = 'LEDGER_INPUT_INVALID',
            DETAIL = 'a reject note is at most 500 characters';
    END IF;
    r := basalt_meta._revert_lock_pending(p_revert_id);
    v_at := clock_timestamp();
    CASE
    WHEN r.ceiling IS NULL AND p_token IS NULL THEN
        v_via := 'LINK_OR_AGENT';
    WHEN r.ceiling IS NOT NULL AND p_token IS NOT NULL AND sha256(p_token) = r.scope_token_hash THEN
        v_via := 'SCOPE_TOKEN';
    ELSE
        PERFORM basalt_meta._widen_refused();
    END CASE;
    UPDATE basalt_meta.reverts x SET rejected_at = v_at, reject_note = v_note WHERE x.revert_id = r.revert_id;
    PERFORM basalt_meta._append(session_user, NULL, 'REVERT_REJECTED', NULL, NULL, NULL, NULL, NULL, NULL,
        pg_catalog.jsonb_strip_nulls(jsonb_build_object('revertId', r.revert_id, 'note', v_note, 'via', v_via)));
    RETURN jsonb_build_object('revertId', r.revert_id, 'status', 'REJECTED', 'rejectedAt', v_at);
END $$;
