package guard

// Version 5 (M3, part 1): the revert plan, read-only. From the ledger rows
// of a scope (one change, one run, one task) the guard builds one chain per
// row, following key changes, and from each chain the inverse write and
// the people-win conflicts (CONTRACT.md, Revert; decisions M3-3, M3-4).
// Nothing here writes the person's tables; version 6 runs the plan on
// trial and version 7 applies it. Same rules as schema.go: forward-only,
// schema-qualified, role names only through Names.render.

const v5Types = `
-- One row as the scope changed it: the first and last in-scope ledger rows,
-- the key it had before (orig_key) and has now (cur_key), the values to
-- restore (old_row of the first) and the values and version the agent left
-- (new_row and new_xmin of the last). broken: someone wrote the row between
-- two in-scope changes.
CREATE TYPE basalt_meta.revert_chain AS (
    table_oid  oid,
    table_name text,
    first_seq  bigint,
    last_seq   bigint,
    first_op   text,
    last_op    text,
    orig_key   jsonb,
    cur_key    jsonb,
    old_row    jsonb,
    new_row    jsonb,
    new_xmin   text,
    cascaded   boolean,
    pruned     boolean,
    broken     boolean,
    change_ids uuid[]
);

-- One line of a revert: the inverse write (op on key, writing set), the
-- row as it is now, and the conflict that skips it (NULL to restore).
CREATE TYPE basalt_meta.revert_item AS (
    table_oid  oid,
    table_name text,
    op         text,
    key        jsonb,
    now        jsonb,
    set        jsonb,
    conflict   text,
    sql_state  text,
    cascaded   boolean,
    change_ids uuid[],
    first_seq  bigint,
    last_seq   bigint
);

-- The latest ledger row of a row, for ALREADY_REVERTED.
CREATE INDEX ledger_table_key ON basalt_meta.ledger (table_oid, row_key, seq) WHERE kind = 'ROW_CHANGE';
CREATE INDEX changes_task ON basalt_meta.changes (task_id, change_id);
`

const v5Plan = `
-- The guard role reads (and, from version 6, writes) guarded tables, only
-- inside the revert functions. attach grants it; basalt init re-attaches
-- every table, so existing ones get the grant too.
CREATE OR REPLACE FUNCTION basalt_meta.attach(p_table regclass, p_reason text) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
    v_pk text[];
BEGIN
    SELECT array_agg(a.attname::text ORDER BY k.ord) INTO v_pk
      FROM pg_index i
      CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY k(attnum, ord)
      JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
     WHERE i.indrelid = p_table AND i.indisprimary;
    IF v_pk IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED',
            DETAIL = format('table %s has no primary key; the guard keys ledger rows by it', p_table),
            HINT = 'add a primary key, or revoke the agent''s write privileges on it';
    END IF;
    EXECUTE format($t$CREATE OR REPLACE TRIGGER basalt_guard AFTER INSERT OR UPDATE OR DELETE ON %s
        FOR EACH ROW WHEN (pg_catalog.pg_has_role(session_user, '{{agents}}', 'MEMBER'))
        EXECUTE FUNCTION basalt_meta.guard_row()$t$, p_table);
    EXECUTE format($t$CREATE OR REPLACE TRIGGER basalt_guard_truncate BEFORE TRUNCATE ON %s
        FOR EACH STATEMENT WHEN (pg_catalog.pg_has_role(session_user, '{{agents}}', 'MEMBER'))
        EXECUTE FUNCTION basalt_meta.guard_truncate()$t$, p_table);
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO {{guard}}',
        (SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = p_table));
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %s TO {{guard}}', p_table);
    INSERT INTO basalt_meta.guarded_tables VALUES (p_table, v_pk, p_reason)
    ON CONFLICT (table_oid) DO UPDATE
       SET pk_cols = excluded.pk_cols, reason = least(basalt_meta.guarded_tables.reason, excluded.reason);
END $$;

-- The changes a scope covers: applied (or already reverted) writes,
-- reverts included, by any agent.
CREATE FUNCTION basalt_meta._revert_scope(p_scope text, p_id uuid) RETURNS TABLE (change_id uuid, agent name)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT c.change_id, c.agent FROM basalt_meta.changes c
     WHERE c.mode = 'APPLY' AND c.status IN ('APPLIED', 'REVERTED')
       AND c.op IN ('INSERT', 'UPDATE', 'DELETE', 'REVERT')
       AND CASE p_scope WHEN 'CHANGE' THEN c.change_id = p_id
                        WHEN 'RUN' THEN c.run_id = p_id
                        ELSE c.task_id = p_id END
$$;

-- One chain per row the scope touched, in ledger order of its first row.
-- A row is followed through key changes; a DELETE then INSERT of the same
-- key continues the chain. The chain breaks when an in-scope change's old
-- version is not the version the previous one left (someone wrote between).
CREATE FUNCTION basalt_meta._revert_chains(p_scope text, p_id uuid) RETURNS SETOF basalt_meta.revert_chain
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
    IF p_scope IS NULL OR p_scope NOT IN ('CHANGE', 'RUN', 'TASK') OR p_id IS NULL THEN
        PERFORM basalt_meta._invalid('scope must be CHANGE, RUN or TASK, with an id');
    END IF;
    FOR l IN
        SELECT x.* FROM basalt_meta.ledger x
         WHERE x.kind = 'ROW_CHANGE'
           AND x.change_id IN (SELECT s.change_id FROM basalt_meta._revert_scope(p_scope, p_id) s)
         ORDER BY x.seq
    LOOP
        v_slot := l.table_oid::text || ':' || l.row_key::text;
        i := (v_map ->> v_slot)::int;
        IF i IS NULL THEN
            c := ROW(l.table_oid, l.table_name, l.seq, l.seq, l.op, l.op, l.row_key, l.row_key, l.old_row, NULL,
                     NULL, coalesce((l.detail ->> 'cascaded')::boolean, false), false, false, '{}'::uuid[]);
            v_chains := v_chains || c;
            i := cardinality(v_chains);
        ELSE
            c := v_chains[i];
            IF (l.op = 'INSERT' AND c.last_op <> 'DELETE')
               OR (l.op <> 'INSERT' AND (l.detail ->> 'xmin') IS DISTINCT FROM c.new_xmin) THEN
                c.broken := true;
            END IF;
        END IF;
        c.last_seq := l.seq;
        c.last_op := l.op;
        c.new_row := l.new_row;
        c.new_xmin := l.detail ->> 'newXmin';
        c.pruned := c.pruned OR l.values_pruned;
        IF NOT l.change_id = ANY (c.change_ids) THEN
            c.change_ids := c.change_ids || l.change_id;
        END IF;
        -- Follow the key: an UPDATE may move the row; a DELETE keeps its slot
        -- so a later INSERT of the same key continues the chain.
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

-- The row with primary key p_key in table p_table, as jsonb, and its
-- version (xmin), or NULLs. p_lock takes a row lock (apply).
CREATE FUNCTION basalt_meta._revert_fetch(p_table oid, p_key jsonb, p_lock boolean, OUT row_now jsonb, OUT row_xmin text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
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
-- Conflicts), first reason that applies. CASCADE and CONSTRAINT need a
-- trial write (version 6).
CREATE FUNCTION basalt_meta._revert_item(c basalt_meta.revert_chain, p_lock boolean) RETURNS basalt_meta.revert_item
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

    SELECT x.* INTO v_last FROM basalt_meta.ledger x
     WHERE x.kind = 'ROW_CHANGE' AND x.table_oid = c.table_oid AND x.seq > c.last_seq
       AND x.row_key IN (c.orig_key, c.cur_key)
     ORDER BY x.seq DESC LIMIT 1;
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

-- The revert's items before any write: one per chain that needs a line
-- (an insert later deleted in scope needs none). Refuses a scope without
-- rows and one over the line cap (M3-9) before reading any row.
CREATE FUNCTION basalt_meta._revert_items(p_scope text, p_id uuid, p_lock boolean) RETURNS basalt_meta.revert_item[]
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    c_max_lines constant int := 1000;
    v_chains basalt_meta.revert_chain[];
BEGIN
    v_chains := ARRAY(SELECT x FROM basalt_meta._revert_chains(p_scope, p_id) x
                       WHERE NOT (x.first_op = 'INSERT' AND x.last_op = 'DELETE')
                       ORDER BY x.first_seq);
    IF cardinality(v_chains) = 0 THEN
        RAISE EXCEPTION USING ERRCODE = 'BS009', MESSAGE = 'NOTHING_TO_REVERT',
            DETAIL = format('%s %s changed no rows that a revert could restore', p_scope, p_id);
    END IF;
    IF cardinality(v_chains) > c_max_lines THEN
        RAISE EXCEPTION USING ERRCODE = 'BS009', MESSAGE = 'REVERT_TOO_LARGE',
            DETAIL = format('%s %s has %s rows, more than %s', p_scope, p_id, cardinality(v_chains), c_max_lines),
            HINT = 'revert it change by change';
    END IF;
    RETURN ARRAY(SELECT basalt_meta._revert_item(x, p_lock) FROM unnest(v_chains) x);
END $$;

-- One revert line (CONTRACT.md, Revert): redacted when p_role cannot
-- SELECT the table.
CREATE FUNCTION basalt_meta._revert_line(it basalt_meta.revert_item, p_role name) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT CASE WHEN coalesce(has_table_privilege(p_role, it.table_oid, 'SELECT'), false)
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
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT coalesce(array_agg(s.line ORDER BY s.line COLLATE "C"), '{}'::text[])
      FROM (SELECT basalt_meta._revert_line(x, p_role) AS line FROM unnest(p_items) x) s
$$;

-- Agent (MCP preview_revert, basalt revert --dry-run): what reverting the
-- scope would do. Read-only.
CREATE FUNCTION basalt_meta.preview_revert(p_scope text, p_scope_id uuid) RETURNS SETOF text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    PERFORM basalt_meta._require_agent();
    RETURN QUERY SELECT u.line
      FROM unnest(basalt_meta._revert_text(basalt_meta._revert_items(p_scope, p_scope_id, false), session_user))
           WITH ORDINALITY u(line, n)
     ORDER BY u.n;
END $$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA basalt_meta FROM PUBLIC;
GRANT EXECUTE ON FUNCTION basalt_meta.preview_revert(text, uuid) TO {{agents}};
`
