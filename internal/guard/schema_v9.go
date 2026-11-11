package guard

// Version 9 (M3 follow-up, decisions N12-1 to N12-6): reverts of any size.
// Up to 1000 lines a revert is prepared, signed and applied in one call as
// in M3. A larger one is a batched plan: every line is stored, the person
// signs one binding over all of them, and the role that prepared it applies
// the plan in batches that are checked here against the signed lines.

const v9Tables = `
-- The order a trial write succeeded in (deletes, updates, re-inserts, FK
-- retries): a batched plan's lines are numbered in it, so applying them
-- in number order lands parents before children across batches.
ALTER TYPE basalt_meta.revert_item ADD ATTRIBUTE step int;

ALTER TABLE basalt_meta.reverts
    ADD COLUMN batched     boolean NOT NULL DEFAULT false,
    ADD COLUMN sample_hash bytea,
    ADD COLUMN covered     uuid[],
    ADD COLUMN signed_at   timestamptz,
    ADD COLUMN apply_by    timestamptz,
    ADD COLUMN batches     int     NOT NULL DEFAULT 0;

-- A batched plan's lines: the signed text (redacted for the preparing
-- role, as every line), the row's ledger chain to re-check it at apply
-- time, and what happened to it. line and chain are values, pruned after
-- 30 days.
CREATE TABLE basalt_meta.revert_lines (
    revert_id uuid NOT NULL REFERENCES basalt_meta.reverts ON DELETE CASCADE,
    line_no   int  NOT NULL,
    line      text,
    chain     basalt_meta.revert_chain,
    outcome   text NOT NULL DEFAULT 'PENDING'
              CONSTRAINT revert_lines_outcome CHECK (outcome IN ('PENDING', 'RESTORED', 'SKIPPED')),
    conflict  text,
    sql_state text,
    batch     int,
    PRIMARY KEY (revert_id, line_no)
);
CREATE INDEX revert_lines_pending ON basalt_meta.revert_lines (revert_id, line_no) WHERE outcome = 'PENDING';
REVOKE ALL ON basalt_meta.revert_lines FROM PUBLIC;
`

const v9Chains = `
-- The key-following walk of version 5, kept for scopes where a row changed
-- its primary key. Its slot map is a jsonb copied on every step, so it is
-- quadratic; _revert_chains uses it only when it must.
CREATE FUNCTION basalt_meta._revert_chains_walk(p_scope text, p_id uuid) RETURNS SETOF basalt_meta.revert_chain
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_chains basalt_meta.revert_chain[] := '{}';
    v_map    jsonb := '{}';
    v_slot   text;
    v_key    jsonb;
    i        int;
    c        basalt_meta.revert_chain;
    l        basalt_meta.ledger;
BEGIN
    FOR l IN
        SELECT x.* FROM basalt_meta.ledger x
         WHERE x.kind = 'ROW_CHANGE'
           AND x.change_id IN (SELECT s.change_id FROM basalt_meta._revert_scope(p_scope, p_id) s)
         ORDER BY x.seq
    LOOP
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

-- A new chain at ledger row l.
CREATE FUNCTION basalt_meta._revert_chain_start(l basalt_meta.ledger) RETURNS basalt_meta.revert_chain
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
    SELECT ROW(l.table_oid, l.table_name, l.seq, l.seq, l.op, l.op, l.row_key, l.row_key, l.old_row, NULL,
               NULL, coalesce((l.detail ->> 'cascaded')::boolean, false), false, false, '{}'::uuid[])::basalt_meta.revert_chain
$$;

-- Chain c continued by ledger row l: broken when someone wrote the row
-- between two in-scope changes (version 5).
CREATE FUNCTION basalt_meta._revert_chain_next(c basalt_meta.revert_chain, l basalt_meta.ledger) RETURNS basalt_meta.revert_chain
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog AS $$
BEGIN
    IF (l.op = 'INSERT' AND c.last_op <> 'DELETE')
       OR (l.op <> 'INSERT' AND (l.detail ->> 'xmin') IS DISTINCT FROM c.new_xmin) THEN
        c.broken := true;
    END IF;
    RETURN c;
END $$;

-- Chain c after ledger row l: what the scope left and which changes wrote it.
CREATE FUNCTION basalt_meta._revert_chain_step(c basalt_meta.revert_chain, l basalt_meta.ledger) RETURNS basalt_meta.revert_chain
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog AS $$
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

-- One chain per row the scope touched (version 5). When no row in scope
-- changed its primary key (the common case) a row keeps its key, so its
-- chain is its ledger rows in key order: one pass, linear in the ledger
-- rows. Otherwise the key-following walk.
CREATE OR REPLACE FUNCTION basalt_meta._revert_chains(p_scope text, p_id uuid) RETURNS SETOF basalt_meta.revert_chain
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    c      basalt_meta.revert_chain;
    l      basalt_meta.ledger;
    v_open boolean := false;
BEGIN
    IF p_scope IS NULL OR p_scope NOT IN ('CHANGE', 'RUN', 'TASK') OR p_id IS NULL THEN
        PERFORM basalt_meta._invalid('scope must be CHANGE, RUN or TASK, with an id');
    END IF;
    IF EXISTS (SELECT 1 FROM basalt_meta.ledger x
                WHERE x.kind = 'ROW_CHANGE' AND x.op = 'UPDATE' AND x.new_row IS NOT NULL
                  AND x.change_id IN (SELECT s.change_id FROM basalt_meta._revert_scope(p_scope, p_id) s)
                  AND basalt_meta._row_key(x.table_oid::regclass, x.new_row) IS DISTINCT FROM x.row_key) THEN
        RETURN QUERY SELECT * FROM basalt_meta._revert_chains_walk(p_scope, p_id);
        RETURN;
    END IF;
    FOR l IN
        SELECT x.* FROM basalt_meta.ledger x
         WHERE x.kind = 'ROW_CHANGE'
           AND x.change_id IN (SELECT s.change_id FROM basalt_meta._revert_scope(p_scope, p_id) s)
         ORDER BY x.table_oid, x.row_key, x.seq
    LOOP
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

-- The chains that need a line (an insert later deleted in scope needs
-- none), in ledger order of their first row. NOTHING_TO_REVERT when none.
-- No cap (decision N12-1).
CREATE FUNCTION basalt_meta._revert_chain_list(p_scope text, p_id uuid) RETURNS basalt_meta.revert_chain[]
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_chains basalt_meta.revert_chain[];
BEGIN
    v_chains := ARRAY(SELECT x FROM basalt_meta._revert_chains(p_scope, p_id) x
                       WHERE NOT (x.first_op = 'INSERT' AND x.last_op = 'DELETE')
                       ORDER BY x.first_seq);
    IF cardinality(v_chains) = 0 THEN
        RAISE EXCEPTION USING ERRCODE = 'BS009', MESSAGE = 'NOTHING_TO_REVERT',
            DETAIL = format('%s %s changed no rows that a revert could restore', p_scope, p_id);
    END IF;
    RETURN v_chains;
END $$;

-- The latest ledger row of a row after p_after, at either of its keys,
-- for ALREADY_REVERTED. One index lookup per key (ledger_table_key): a
-- plain ORDER BY seq DESC LIMIT 1 scans the ledger backwards, which made
-- planning a large revert quadratic.
CREATE FUNCTION basalt_meta._revert_last(p_table oid, p_keys jsonb[], p_after bigint) RETURNS basalt_meta.ledger
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT x.* FROM basalt_meta.ledger x
     WHERE x.seq = (SELECT max(s.seq) FROM unnest(p_keys) k
                     CROSS JOIN LATERAL (SELECT max(y.seq) AS seq FROM basalt_meta.ledger y
                                          WHERE y.kind = 'ROW_CHANGE' AND y.table_oid = p_table AND y.row_key = k
                                            AND y.seq > p_after) s)
$$;

-- The inverse of one chain and its static conflict (version 5), with the
-- ALREADY_REVERTED lookup through _revert_last.
CREATE OR REPLACE FUNCTION basalt_meta._revert_item(c basalt_meta.revert_chain, p_lock boolean) RETURNS basalt_meta.revert_item
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
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
                   WHERE NOT EXISTS (SELECT 1 FROM pg_attribute a
                                      WHERE a.attrelid = c.table_oid AND a.attname = k AND a.attnum > 0
                                        AND NOT a.attisdropped)) THEN
        it.conflict := 'SCHEMA_CHANGED';
        RETURN it;
    END IF;
    SELECT coalesce(array_agg(a.attname::text), '{}') INTO v_gen
      FROM pg_attribute a
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

-- The revert's items before any write (version 5, without the line cap).
CREATE OR REPLACE FUNCTION basalt_meta._revert_items(p_scope text, p_id uuid, p_lock boolean) RETURNS basalt_meta.revert_item[]
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT ARRAY(SELECT basalt_meta._revert_item(x, p_lock)
                   FROM unnest(basalt_meta._revert_chain_list(p_scope, p_id)) x)
$$;
`

const v9Execute = `
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
`

const v9Prepare = `
-- Agent, as the CLI's relay (version 6): store a revert for the person to
-- sign. Up to 1000 lines it is applied in one call. Above, it is a batched
-- plan: every line is stored, numbered in execution order, and the binding
-- adds batched and sampleHash over the lines the link carries (the first
-- 1000, SKIP lines first; decision N12-4). rowsHash covers every line.
CREATE OR REPLACE FUNCTION basalt_meta.prepare_revert(p_scope text, p_scope_id uuid, p_intent text)
RETURNS TABLE (revert_id uuid, binding_text text, expires_at timestamptz, lines text[])
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
#variable_conflict use_column
DECLARE
    c_ttl       constant interval := interval '1 hour';
    c_max_lines constant int := 1000; -- one-call revert and lines in a link (M3-9, N12-4)
    v_id        uuid := basalt_meta._uuidv7();
    v_expires   timestamptz := now() + c_ttl;
    v_chains    basalt_meta.revert_chain[];
    v_items     basalt_meta.revert_item[];
    v_lines     text[];
    v_sample    text[];
    v_rows      int;
    v_agents    name[];
    v_covered   uuid[];
    v_hash      bytea;
    v_sample_h  bytea;
    v_batched   boolean;
    v_text      text;
BEGIN
    PERFORM basalt_meta._require_agent();
    PERFORM basalt_meta._check_text('intent', p_intent, 2000, true);
    v_chains := basalt_meta._revert_chain_list(p_scope, p_scope_id);
    v_items := basalt_meta._revert_trial_items(ARRAY(SELECT basalt_meta._revert_item(x, false) FROM unnest(v_chains) x));
    v_lines := basalt_meta._revert_text(v_items, session_user);
    SELECT count(x.table_oid)::int INTO v_rows FROM unnest(v_items) x WHERE x.conflict IS NULL;
    IF v_rows = 0 THEN
        RAISE EXCEPTION USING ERRCODE = 'BS009', MESSAGE = 'NOTHING_TO_REVERT',
            DETAIL = format('every row of %s %s would be skipped', p_scope, p_scope_id);
    END IF;
    SELECT array_agg(DISTINCT s.agent ORDER BY s.agent), array_agg(s.change_id ORDER BY s.change_id)
      INTO v_agents, v_covered
      FROM basalt_meta._revert_scope(p_scope, p_scope_id) s;
    v_hash := sha256(convert_to(array_to_string(v_lines, E'\n'), 'UTF8'));
    v_batched := cardinality(v_lines) > c_max_lines;
    v_sample := v_lines;
    IF v_batched THEN
        v_sample := ARRAY(SELECT u.l FROM unnest(v_lines) WITH ORDINALITY u(l, n)
                           ORDER BY (u.l::jsonb ->> 'action') = 'RESTORE', u.n
                           LIMIT c_max_lines);
        v_sample_h := sha256(convert_to(array_to_string(v_sample, E'\n'), 'UTF8'));
    END IF;
    v_text := (jsonb_build_object(
        'kind', 'REVERT', 'revertId', v_id, 'database', current_database(), 'scope', p_scope, 'scopeId', p_scope_id,
        'agents', to_jsonb(v_agents::text[]), 'intent', p_intent, 'rows', v_rows,
        'skipped', cardinality(v_lines) - v_rows, 'rowsHash', encode(v_hash, 'hex'),
        'expiresAt', to_char(v_expires AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'requestedBy', session_user)
        || CASE WHEN v_batched THEN jsonb_build_object('batched', true, 'sampleHash', encode(v_sample_h, 'hex'))
                ELSE '{}'::jsonb END)::text;
    INSERT INTO basalt_meta.reverts (revert_id, scope, scope_id, agents, requested_by, intent, lines, rows, skipped,
                                     rows_hash, binding_text, binding, expires_at, batched, sample_hash, covered)
    VALUES (v_id, p_scope, p_scope_id, v_agents, session_user, p_intent, v_sample, v_rows, cardinality(v_lines) - v_rows,
            v_hash, v_text, sha256(convert_to(v_text, 'UTF8')), v_expires, v_batched, v_sample_h, v_covered);
    IF v_batched THEN
        -- Execution order: the writes that landed on trial in the order they
        -- landed, then the lines the trial skipped.
        INSERT INTO basalt_meta.revert_lines (revert_id, line_no, line, chain)
        SELECT v_id, row_number() OVER (ORDER BY it.step NULLS LAST, it.first_seq),
               basalt_meta._revert_line(it, session_user), ch
          FROM unnest(v_items) it JOIN unnest(v_chains) ch ON ch.first_seq = it.first_seq;
    END IF;
    PERFORM basalt_meta._append(session_user, NULL, 'REVERT_PENDING', NULL, NULL, NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', v_id, 'scope', p_scope, 'scopeId', p_scope_id, 'intent', p_intent,
                           'rows', v_rows, 'skipped', cardinality(v_lines) - v_rows,
                           'rowsHash', encode(v_hash, 'hex'), 'expiresAt', v_expires)
        || CASE WHEN v_batched THEN jsonb_build_object('batched', true) ELSE '{}'::jsonb END);
    revert_id := v_id;
    binding_text := v_text;
    expires_at := v_expires;
    lines := v_sample;
    RETURN NEXT;
END $$;
`

const v9Apply = `
-- The skipped lines of a plan as the preparing role saw them, for ledger
-- details: table, key or row hash, reason; no values.
CREATE FUNCTION basalt_meta._revert_skips(p_revert uuid, p_lines int[]) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
               'line', l.line_no, 'table', l.line::jsonb -> 'table', 'key', l.line::jsonb -> 'key',
               'rowHash', l.line::jsonb -> 'rowHash', 'conflict', l.conflict, 'sqlState', l.sql_state))
             ORDER BY l.line_no), '[]'::jsonb)
      FROM basalt_meta.revert_lines l
     WHERE l.revert_id = p_revert AND l.outcome = 'SKIPPED' AND (p_lines IS NULL OR l.line_no = ANY (p_lines))
$$;

-- A batched plan's totals: lines restored, skipped and pending.
CREATE FUNCTION basalt_meta._revert_progress(p_revert uuid, OUT restored int, OUT skipped int, OUT pending int)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT count(l.line_no) FILTER (WHERE l.outcome = 'RESTORED')::int,
           count(l.line_no) FILTER (WHERE l.outcome = 'SKIPPED')::int,
           count(l.line_no) FILTER (WHERE l.outcome = 'PENDING')::int
      FROM basalt_meta.revert_lines l WHERE l.revert_id = p_revert
$$;

-- The person's signature over a batched plan (decision N12-6): open the
-- revert's change record, mark the SKIP lines skipped, start the 24-hour
-- window (N12-2), and record REVERT_SIGNED. No row of the person's tables
-- is written here.
CREATE FUNCTION basalt_meta._revert_sign(r basalt_meta.reverts, p_credential_id bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    c_window   constant interval := interval '24 hours';
    v_change   uuid := basalt_meta._uuidv7();
    v_apply_by timestamptz := now() + c_window;
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
       SET signed_at = now(), apply_by = v_apply_by, credential_id = p_credential_id, change_id = v_change
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

-- Any relay (version 7): verify the person's assertion over a prepared
-- revert and run it in the same call; for a batched plan, record the
-- signature only (_revert_sign).
CREATE OR REPLACE FUNCTION basalt_meta.apply_revert(
    p_revert_id uuid, p_credential_id bytea, p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
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
    IF r.signed_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_invalid('revert already signed; the agent applies it in batches');
    END IF;
    IF r.expires_at <= now() THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'REVERT_EXPIRED',
            DETAIL = format('revert %s expired at %s; prepare it again', r.revert_id, r.expires_at);
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
    v_items := basalt_meta._revert_execute(basalt_meta._revert_items(r.scope, r.scope_id, true));
    v_lines := basalt_meta._revert_text(v_items, r.requested_by);
    DELETE FROM basalt_meta.revert_running x WHERE x.tx = pg_current_xact_id();
    IF sha256(convert_to(array_to_string(v_lines, E'\n'), 'UTF8')) <> r.rows_hash THEN
        PERFORM basalt_meta._revert_invalid('rows changed since the preview; nothing was reverted, prepare the revert again');
    END IF;

    SELECT count(x.table_oid)::int INTO v_rows FROM unnest(v_items) x WHERE x.conflict IS NULL;
    UPDATE basalt_meta.changes x SET rows = v_rows WHERE x.change_id = v_change;
    -- A change is REVERTED when none of its rows was skipped; a partly
    -- reverted change stays APPLIED and names the revert (M3-8).
    UPDATE basalt_meta.changes c
       SET reverted_by = coalesce(c.reverted_by, '{}'::uuid[]) || v_change,
           status = CASE WHEN EXISTS (SELECT 1 FROM unnest(v_items) x WHERE x.conflict IS NOT NULL AND c.change_id = ANY (x.change_ids))
                         THEN c.status ELSE 'REVERTED' END
     WHERE c.change_id IN (SELECT s.change_id FROM basalt_meta._revert_scope(r.scope, r.scope_id) s)
       AND (EXISTS (SELECT 1 FROM unnest(v_items) x WHERE x.conflict IS NULL AND c.change_id = ANY (x.change_ids))
            OR NOT EXISTS (SELECT 1 FROM unnest(v_items) x WHERE c.change_id = ANY (x.change_ids)));
    UPDATE basalt_meta.reverts x SET applied_at = now(), credential_id = p_credential_id, change_id = v_change
     WHERE x.revert_id = r.revert_id;

    SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
               'table', l -> 'table', 'key', l -> 'key', 'rowHash', l -> 'rowHash',
               'conflict', l -> 'conflict', 'sqlState', l -> 'sqlState')) ORDER BY n), '[]'::jsonb)
      INTO v_skipped
      FROM unnest(v_lines) WITH ORDINALITY u(t, n) CROSS JOIN LATERAL (SELECT u.t::jsonb AS l) j
     WHERE l ->> 'action' = 'SKIP';
    PERFORM basalt_meta._append(session_user, v_change, 'REVERTED', NULL, 'REVERT', NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', r.revert_id, 'scope', r.scope, 'scopeId', r.scope_id, 'intent', r.intent,
                           'credentialId', encode(p_credential_id, 'hex'), 'binding', encode(r.binding, 'hex'),
                           'rows', v_rows, 'skipped', v_skipped));
    RETURN jsonb_build_object('changeId', v_change, 'rows', v_rows, 'skipped', cardinality(v_lines) - v_rows);
END $$;

-- One line of a signed plan re-checked with its row locked (decision
-- N12-5): the item recomputed from the stored chain, skipped as
-- CHANGED_AFTER when it no longer matches the signed line.
CREATE FUNCTION basalt_meta._revert_recheck(l basalt_meta.revert_lines, p_role name) RETURNS basalt_meta.revert_item
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    it basalt_meta.revert_item := basalt_meta._revert_item(l.chain, true);
BEGIN
    IF it.conflict IS NULL AND basalt_meta._revert_line(it, p_role) IS DISTINCT FROM l.line THEN
        it.conflict := 'CHANGED_AFTER';
    END IF;
    RETURN it;
END $$;

-- The last batch of a plan: the plan is applied, and each covered change
-- is REVERTED when every line naming it was restored (changes with no
-- line count as restored, as in M3-8).
CREATE FUNCTION basalt_meta._revert_finish(r basalt_meta.reverts, p_batches int) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_progress record;
BEGIN
    SELECT * INTO v_progress FROM basalt_meta._revert_progress(r.revert_id);
    UPDATE basalt_meta.reverts x SET applied_at = now() WHERE x.revert_id = r.revert_id;
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
           status = CASE WHEN coalesce(v.all_restored, true) THEN 'REVERTED' ELSE c.status END
      FROM covered v
     WHERE c.change_id = v.cid AND (v.any_restored OR v.all_restored IS NULL);
    PERFORM basalt_meta._append(session_user, r.change_id, 'REVERTED', NULL, 'REVERT', NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', r.revert_id, 'scope', r.scope, 'scopeId', r.scope_id, 'intent', r.intent,
                           'rows', v_progress.restored, 'skipped', v_progress.skipped, 'batches', p_batches));
END $$;

-- The role that prepared a signed batched plan: apply up to 200 of its
-- pending lines (decisions N12-3, N12-5, N12-6). Checked against the
-- signed plan before anything is written: only lines of this plan, each
-- at most once, within 24 hours of the signature. Each line is re-checked
-- with its row locked; a row someone changed is skipped (people win).
CREATE FUNCTION basalt_meta.apply_revert_batch(p_revert_id uuid, p_lines int[]) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
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
    IF r.apply_by <= now() THEN
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
`

const v9Views = `
-- Retention (version 7) plus a plan's lines: their text and chain are
-- values (30 days); the rows go with their revert after 1 year.
CREATE OR REPLACE FUNCTION basalt_meta._prune(p_now timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    c_values_ttl constant interval := interval '30 days';
    c_meta_ttl   constant interval := interval '1 year';
    v_values  bigint := 0;
    v_rows    bigint := 0;
    v_expired bigint := 0;
    v_cut     bigint;
BEGIN
    UPDATE basalt_meta.changes c SET status = 'APPROVAL_EXPIRED'
      FROM basalt_meta.approvals a
     WHERE a.held_change = c.change_id AND c.status = 'APPROVAL_PENDING'
       AND a.used_by_change IS NULL AND a.expires_at <= p_now;
    GET DIAGNOSTICS v_expired = ROW_COUNT;

    UPDATE basalt_meta.ledger SET old_row = NULL, new_row = NULL, values_pruned = true
     WHERE NOT values_pruned AND at < p_now - c_values_ttl AND (old_row IS NOT NULL OR new_row IS NOT NULL);
    GET DIAGNOSTICS v_values = ROW_COUNT;
    UPDATE basalt_meta.changes SET params = NULL WHERE params IS NOT NULL AND at < p_now - c_values_ttl;
    UPDATE basalt_meta.approvals SET params = NULL, lines = NULL, binding_text = NULL, statement = NULL
     WHERE created_at < p_now - c_values_ttl AND (lines IS NOT NULL OR binding_text IS NOT NULL);
    UPDATE basalt_meta.reverts SET lines = NULL, binding_text = NULL
     WHERE created_at < p_now - c_values_ttl AND (lines IS NOT NULL OR binding_text IS NOT NULL);
    UPDATE basalt_meta.revert_lines l SET line = NULL, chain = NULL
      FROM basalt_meta.reverts r
     WHERE r.revert_id = l.revert_id AND r.created_at < p_now - c_values_ttl AND l.line IS NOT NULL;

    SELECT max(seq) INTO v_cut FROM basalt_meta.ledger WHERE at < p_now - c_meta_ttl;
    IF v_cut IS NOT NULL THEN
        UPDATE basalt_meta.chain_anchor a SET seq = l.seq, hash = l.hash
          FROM basalt_meta.ledger l WHERE a.id AND l.seq = v_cut;
        DELETE FROM basalt_meta.ledger WHERE seq <= v_cut;
        GET DIAGNOSTICS v_rows = ROW_COUNT;
        DELETE FROM basalt_meta.changes WHERE at < p_now - c_meta_ttl;
        DELETE FROM basalt_meta.runs WHERE started_at < p_now - c_meta_ttl;
        DELETE FROM basalt_meta.approvals WHERE created_at < p_now - c_meta_ttl;
        DELETE FROM basalt_meta.reverts WHERE created_at < p_now - c_meta_ttl;
    END IF;

    IF v_values + v_rows > 0 THEN
        PERFORM basalt_meta._append(session_user, NULL, 'PRUNED', NULL, NULL, NULL, NULL, NULL, NULL,
            jsonb_build_object('valuesPruned', v_values, 'rowsDeleted', v_rows));
    END IF;
    RETURN jsonb_build_object('valuesPruned', v_values, 'rowsDeleted', v_rows, 'approvalsExpired', v_expired);
END $$;

-- The reverts the calling role prepared (version 6), with a batched plan's
-- signature, window and progress. APPLYING: signed, lines pending, within
-- the window; EXPIRED: not signed in time, or not finished in time.
CREATE OR REPLACE VIEW basalt_meta.agent_reverts WITH (security_barrier = true) AS
    SELECT r.revert_id, r.scope, r.scope_id, r.agents, r.intent, r.rows, r.skipped,
           CASE WHEN r.applied_at IS NOT NULL THEN 'APPLIED'
                WHEN r.signed_at IS NOT NULL AND r.apply_by > pg_catalog.now() THEN 'APPLYING'
                WHEN r.signed_at IS NOT NULL THEN 'EXPIRED'
                WHEN r.expires_at <= pg_catalog.now() THEN 'EXPIRED'
                ELSE 'PENDING' END AS status,
           r.created_at, r.expires_at, r.applied_at, r.change_id, r.binding_text, r.lines,
           r.batched, r.signed_at, r.apply_by, r.batches, p.restored, p.skipped AS skipped_now, p.pending
      FROM basalt_meta.reverts r
      -- Inline, not _revert_progress: a view runs functions as its caller.
      LEFT JOIN LATERAL (SELECT count(l.line_no) FILTER (WHERE l.outcome = 'RESTORED')::int AS restored,
                                count(l.line_no) FILTER (WHERE l.outcome = 'SKIPPED')::int AS skipped,
                                count(l.line_no) FILTER (WHERE l.outcome = 'PENDING')::int AS pending
                           FROM basalt_meta.revert_lines l WHERE l.revert_id = r.revert_id) p ON r.batched
     WHERE r.requested_by = session_user;

-- The lines of the batched plans the calling role prepared.
CREATE VIEW basalt_meta.agent_revert_lines WITH (security_barrier = true) AS
    SELECT l.revert_id, l.line_no, l.line, l.outcome, l.conflict, l.sql_state, l.batch
      FROM basalt_meta.revert_lines l
      JOIN basalt_meta.reverts r ON r.revert_id = l.revert_id
     WHERE r.requested_by = session_user;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA basalt_meta FROM PUBLIC;
GRANT SELECT ON basalt_meta.agent_revert_lines TO {{agents}};
GRANT EXECUTE ON FUNCTION basalt_meta.apply_revert_batch(uuid, int[]) TO {{agents}};
`
