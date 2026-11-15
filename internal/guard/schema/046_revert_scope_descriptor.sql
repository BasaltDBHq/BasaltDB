-- Version 20: revert scope, the core (owner decisions RS-1 to RS-4;
-- CONTRACT.md, basalt_meta "Version 20" and Revert "The scope descriptor").
--
-- What a revert covers is now its scope descriptor (reverts.selection): a
-- CHANGE, RUN or TASK narrowed to some agents, runs and tables. scope,
-- scope_id and agents become columns generated from it, so they cannot
-- disagree with it. preview_revert and prepare_revert take the descriptor
-- and accept, from an agent role, only its own work: agents exactly
-- [session_user], its own change or run or a task it ran in, and runs and
-- tables inside that work. The binding carries the descriptor as select
-- (and proposed when a later rescope changes it), and apply_revert refuses
-- a binding whose select is not the stored one and recomputes the lines
-- from the stored selection.
--
-- Unsigned PENDING reverts are expired: their bindings have no select.
-- Signed large plans keep running: apply_revert_batch checks each line
-- against its stored signed text, never the binding's select.
--
-- Breaking (AE-11): preview_revert and prepare_revert change signatures.
-- Rescope, reset and reject come in later versions of this plan.

-- 16 random bytes for a revert's rescope nonce, from pg_strong_random
-- (gen_random_uuid): two v4 uuids carry 244 random bits, hashed down.
CREATE OR REPLACE FUNCTION basalt_meta._revert_nonce() RETURNS bytea
LANGUAGE sql VOLATILE SET search_path = pg_catalog AS $$
    SELECT substring(sha256(uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid())) FROM 1 FOR 16)
$$;

-- The agents of a descriptor as roles, NULL when it selects every agent.
-- IMMUTABLE: reverts.agents is generated from it.
CREATE OR REPLACE FUNCTION basalt_meta._revert_select_agents(p_sel jsonb) RETURNS name[]
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
    SELECT CASE WHEN jsonb_typeof(p_sel -> 'agents') = 'array'
                THEN ARRAY(SELECT a::name FROM jsonb_array_elements_text(p_sel -> 'agents') a) END
$$;

-- True when a descriptor covers changes not made by p_role: its agents is
-- null (every agent) or names another role. IMMUTABLE: reverts.widened is
-- generated from it.
CREATE OR REPLACE FUNCTION basalt_meta._widened(p_sel jsonb, p_role name) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
    SELECT jsonb_typeof(p_sel -> 'agents') IS DISTINCT FROM 'array'
        OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(p_sel -> 'agents') a WHERE a <> p_role::text)
$$;

-- A scope descriptor refused (BS011): DETAIL is the reason the engine maps
-- (SHAPE, STORE_RESERVED, FILTER_CAP, NOT_OWN_CHANGE, NOT_OWN_RUN,
-- NOT_OWN_TASK, FILTER), HINT what to change.
CREATE OR REPLACE FUNCTION basalt_meta._scope_refused(p_detail text, p_hint text) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'BS011', MESSAGE = 'SCOPE_REFUSED', DETAIL = p_detail, HINT = p_hint;
END $$;

-- A JSON list of the descriptor (agents, runs or tables) sorted by its text
-- COLLATE "C" and deduplicated, or JSON null.
CREATE OR REPLACE FUNCTION basalt_meta._revert_select_list(p_list jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
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
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog AS $$
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
-- its runs (every run when null). Version 5's _revert_scope with the
-- agents and runs filters.
CREATE OR REPLACE FUNCTION basalt_meta._revert_scope(p_sel jsonb) RETURNS TABLE (change_id uuid, agent name)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT c.change_id, c.agent FROM basalt_meta.changes c
     WHERE c.mode = 'APPLY' AND c.status IN ('APPLIED', 'REVERTED')
       AND c.op IN ('INSERT', 'UPDATE', 'DELETE', 'REVERT')
       AND CASE p_sel ->> 'scope' WHEN 'CHANGE' THEN c.change_id = (p_sel ->> 'scopeId')::uuid
                                  WHEN 'RUN' THEN c.run_id = (p_sel ->> 'scopeId')::uuid
                                  ELSE c.task_id = (p_sel ->> 'scopeId')::uuid END
       AND (jsonb_typeof(p_sel -> 'agents') IS DISTINCT FROM 'array' OR (p_sel -> 'agents') ? c.agent::text)
       AND (jsonb_typeof(p_sel -> 'runs') IS DISTINCT FROM 'array' OR (p_sel -> 'runs') ? c.run_id::text)
$$;

-- The ledger rows a descriptor covers: the row changes of its changes, on
-- its tables (every table when null). A table filter filters rows, not
-- changes: a change that wrote two tables can be half selected.
CREATE OR REPLACE FUNCTION basalt_meta._revert_rows(p_sel jsonb) RETURNS SETOF basalt_meta.ledger
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT x.* FROM basalt_meta.ledger x
     WHERE x.kind = 'ROW_CHANGE'
       AND x.change_id IN (SELECT s.change_id FROM basalt_meta._revert_scope(p_sel) s)
       AND (jsonb_typeof(p_sel -> 'tables') IS DISTINCT FROM 'array' OR (p_sel -> 'tables') ? x.table_name)
$$;

-- The changes a revert of the descriptor covers: those of _revert_scope
-- with a row change on its tables (all of them without a table filter).
-- They get the revert in reverted_by.
CREATE OR REPLACE FUNCTION basalt_meta._revert_covered(p_sel jsonb) RETURNS SETOF uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT s.change_id FROM basalt_meta._revert_scope(p_sel) s
     WHERE jsonb_typeof(p_sel -> 'tables') IS DISTINCT FROM 'array'
        OR EXISTS (SELECT 1 FROM basalt_meta.ledger x
                    WHERE x.kind = 'ROW_CHANGE' AND x.change_id = s.change_id AND (p_sel -> 'tables') ? x.table_name)
$$;

-- True when a revert of the descriptor covers every row change of change
-- p_change (no table filter leaves one out), so the change may become
-- REVERTED.
CREATE OR REPLACE FUNCTION basalt_meta._revert_whole(p_sel jsonb, p_change uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT jsonb_typeof(p_sel -> 'tables') IS DISTINCT FROM 'array'
        OR NOT EXISTS (SELECT 1 FROM basalt_meta.ledger x
                        WHERE x.kind = 'ROW_CHANGE' AND x.change_id = p_change
                          AND NOT (p_sel -> 'tables') ? x.table_name)
$$;

-- The descriptor p as an agent role's own proposal (RS-1): normalized,
-- agents exactly [session_user], its own change or run or a task it ran in
-- (any of its runs with that task id), and every listed run and table
-- inside that work. Refusals name only what the caller sent, with one
-- fixed text per kind, so another agent's change, run or table reads like
-- one that does not exist.
CREATE OR REPLACE FUNCTION basalt_meta._revert_own_select(p jsonb) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_sel     jsonb := basalt_meta._revert_select_norm(p);
    v_role    name := session_user;
    v_id      uuid := (v_sel ->> 'scopeId')::uuid;
    v_own     jsonb;
    v_refused text[];
BEGIN
    IF v_sel -> 'agents' IS DISTINCT FROM jsonb_build_array(v_role::text) THEN
        PERFORM basalt_meta._scope_refused('FILTER', 'agents is exactly your own role: an agent proposes only its own work');
    END IF;
    CASE v_sel ->> 'scope'
    WHEN 'CHANGE' THEN
        IF NOT EXISTS (SELECT 1 FROM basalt_meta.changes c WHERE c.change_id = v_id AND c.agent = v_role) THEN
            PERFORM basalt_meta._scope_refused('NOT_OWN_CHANGE', format('change %s is not one of your changes', v_id));
        END IF;
    WHEN 'RUN' THEN
        IF NOT EXISTS (SELECT 1 FROM basalt_meta.runs r WHERE r.run_id = v_id AND r.agent = v_role) THEN
            PERFORM basalt_meta._scope_refused('NOT_OWN_RUN', format('run %s is not one of your runs', v_id));
        END IF;
    ELSE
        IF NOT EXISTS (SELECT 1 FROM basalt_meta.runs r WHERE r.task_id = v_id AND r.agent = v_role) THEN
            PERFORM basalt_meta._scope_refused('NOT_OWN_TASK', format('you have no run in task %s', v_id));
        END IF;
    END CASE;
    v_own := v_sel || jsonb_build_object('runs', NULL, 'tables', NULL);
    v_refused := ARRAY(
        SELECT format('run %s is not one of your runs in task %s', u.run, v_id)
          FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(v_sel -> 'runs') = 'array' THEN v_sel -> 'runs' ELSE '[]' END) u(run)
         WHERE NOT EXISTS (SELECT 1 FROM basalt_meta.runs r
                            WHERE r.run_id = u.run::uuid AND r.task_id = v_id AND r.agent = v_role)
        UNION ALL
        SELECT format('%s has no change of yours in this scope', u.tbl)
          FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(v_sel -> 'tables') = 'array' THEN v_sel -> 'tables' ELSE '[]' END) u(tbl)
         WHERE NOT EXISTS (SELECT 1 FROM basalt_meta._revert_rows(v_own) x WHERE x.table_name = u.tbl));
    IF cardinality(v_refused) > 0 THEN
        PERFORM basalt_meta._scope_refused('FILTER', array_to_string(v_refused, '; '));
    END IF;
    RETURN v_sel;
END $$;
