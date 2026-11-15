-- The revert chain functions over a scope descriptor.

-- Versions 5 and 9's chain functions over a descriptor instead of
-- (scope, id): the same walk over _revert_rows.
CREATE OR REPLACE FUNCTION basalt_meta._revert_chains_walk(p_sel jsonb) RETURNS SETOF basalt_meta.revert_chain
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
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
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
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
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
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT ARRAY(SELECT basalt_meta._revert_item(x, p_lock)
                   FROM unnest(basalt_meta._revert_chain_list(p_sel, false)) x)
$$;

-- Lines per agent role among items, RESTORE and SKIP: a line counts for
-- every agent with a change in it. The binding's agentRows.
CREATE OR REPLACE FUNCTION basalt_meta._revert_agent_rows(p_items basalt_meta.revert_item[]) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
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
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
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
