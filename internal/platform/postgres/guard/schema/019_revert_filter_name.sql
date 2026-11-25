-- Version 9: a tables entry of a revert scope descriptor that is not one
-- schema.table name is refused with its own detail, NAME, and a hint that
-- names the first such entry, so the caller tells it apart by the detail
-- and knows which entry to drop. A tables entry that is not a string, and
-- every other shape refusal, keep SHAPE and their hints.

-- The descriptor checked for shape and normalized (CONTRACT.md, The scope
-- descriptor): every key present, lists sorted and deduplicated, null for
-- all, ids in canonical form. Reads nothing but its argument, so a refusal
-- here says nothing about any data: SHAPE, NAME (a tables entry that is
-- not one schema.table name), STORE_RESERVED (RS-4) or FILTER_CAP (at most
-- 20 runs and 20 tables).
CREATE OR REPLACE FUNCTION basalt_meta._revert_select_norm(p jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_max_filter constant int  := 20; -- runs and tables in a descriptor (owner, Q10)
    c_max_name   constant int  := 63; -- NAMEDATALEN - 1
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
        IF EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(p -> v_list) e
                    WHERE jsonb_typeof(e) IS DISTINCT FROM 'string'
                       OR CASE v_list WHEN 'agents' THEN length(e #>> '{}') NOT BETWEEN 1 AND c_max_name
                                      WHEN 'runs' THEN (e #>> '{}') !~ c_uuid
                                      ELSE false END) THEN
            PERFORM basalt_meta._scope_refused('SHAPE', CASE v_list WHEN 'agents' THEN 'agents are role names'
                                                                     WHEN 'runs' THEN 'runs are run ids'
                                                                     ELSE 'tables are schema.table names' END);
        END IF;
        -- Every entry is a string here. The first, in the caller's order,
        -- that is not one schema.table name is named, cut to the longest
        -- name there is.
        IF v_list = 'tables' THEN
            SELECT e INTO v_bad FROM pg_catalog.jsonb_array_elements_text(p -> 'tables') WITH ORDINALITY AS t(e, n)
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
        'tables', basalt_meta._revert_select_list(p -> 'tables'));
END $$;
