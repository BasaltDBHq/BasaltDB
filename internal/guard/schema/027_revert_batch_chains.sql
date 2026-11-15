-- The revert chain walk for plans of any size.

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
