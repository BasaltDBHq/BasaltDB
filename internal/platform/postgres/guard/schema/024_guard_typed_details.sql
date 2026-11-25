-- Version 11: typed details. The guard answers with a code the engine
-- reads, never a sentence it has to match: apply_revert's REVERT_INVALID
-- for a signed or applied revert, a revoked passkey and rows changed since
-- the preview carry the code as DETAIL and the sentence as HINT, as
-- SCOPE_REFUSED and WIDEN_REFUSED do, and so does NOTHING_TO_REVERT for a
-- scope that changed no row a revert could restore. Every other refusal
-- keeps its detail. _revert_select_norm names the first bad entry of a
-- descriptor's agents, runs or resources.

-- REVERT_INVALID with the typed detail p_code and the sentence p_hint.
-- The codes: ALREADY_APPLIED, ALREADY_SIGNED, PASSKEY_REVOKED,
-- ROWS_CHANGED (CONTRACT.md, basalt_meta, Guard errors).
CREATE OR REPLACE FUNCTION basalt_meta._revert_refused(p_code text, p_hint text) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'REVERT_INVALID', DETAIL = p_code, HINT = p_hint;
END $$;


-- Any relay (the engine for the revert page, with the agent credential):
-- verify the person's assertion over a prepared revert and run it in the
-- same call, so there is no signed-but-unapplied revert to replay; for a
-- batched plan, record the signature only (_revert_sign). The revert row is
-- locked before any check, so a rescope and a signature cannot
-- interleave. The binding must carry the stored selection as its select,
-- and the lines are recomputed from that selection, never from the
-- binding. applied_at reads the wall clock. A revert already applied or
-- signed, a revoked passkey and rows changed since the preview are refused
-- with their typed detail (_revert_refused); a revoked passkey is told by
-- the passkey's record, before what else the assertion check refused.
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
        PERFORM basalt_meta._revert_refused('ALREADY_APPLIED', 'revert already applied');
    END IF;
    IF r.rejected_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_invalid('the person rejected this revert; nothing was reverted');
    END IF;
    IF r.signed_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_refused('ALREADY_SIGNED', 'revert already signed; the agent applies it in batches');
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
        IF EXISTS (SELECT 1 FROM basalt_meta.passkeys k
                    WHERE k.credential_id = p_credential_id AND k.revoked_at IS NOT NULL) THEN
            PERFORM basalt_meta._revert_refused('PASSKEY_REVOKED', 'passkey revoked');
        END IF;
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
        PERFORM basalt_meta._revert_refused('ROWS_CHANGED', 'rows changed since the preview; nothing was reverted, prepare the revert again');
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

-- The chains that need a line, in ledger order of their first row.
-- NOTHING_TO_REVERT when none, unless p_empty_ok (a task proposal the
-- person may widen): detail READS_ONLY, the hint naming the scope.
CREATE OR REPLACE FUNCTION basalt_meta._revert_chain_list(p_sel jsonb, p_empty_ok boolean) RETURNS basalt_meta.revert_chain[]
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_chains basalt_meta.revert_chain[];
BEGIN
    v_chains := ARRAY(SELECT x FROM basalt_meta._revert_chains(p_sel) x
                       WHERE NOT (x.first_op = 'INSERT' AND x.last_op = 'DELETE')
                       ORDER BY x.first_seq);
    IF cardinality(v_chains) = 0 AND NOT p_empty_ok THEN
        RAISE EXCEPTION USING ERRCODE = 'BS009', MESSAGE = 'NOTHING_TO_REVERT', DETAIL = 'READS_ONLY',
            HINT = format('%s %s changed no rows that a revert could restore', p_sel ->> 'scope', p_sel ->> 'scopeId');
    END IF;
    RETURN v_chains;
END $$;

-- The descriptor checked for shape and normalized (CONTRACT.md, The scope
-- descriptor), in the form texts carry it: agents agent:<name>, resources
-- schema.table names. Every key present, lists sorted and deduplicated,
-- null for all, ids in canonical form. Reads nothing but its argument, so a
-- refusal here says nothing about any data: SHAPE, NAME (a resources entry
-- that is not one schema.table name), STORE_RESERVED (RS-4) or FILTER_CAP
-- (at most 20 runs and 20 resources). A refusal for an entry names the
-- first bad entry in the caller's order. _revert_select_internal maps it
-- to the guard's own form.
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
        -- The first entry, in the caller's order, of the wrong kind is
        -- named: a string as it is, anything else as JSON, cut to the
        -- longest schema.table name there is.
        SELECT CASE WHEN jsonb_typeof(e) = 'string' THEN e #>> '{}' ELSE e::text END INTO v_bad
          FROM pg_catalog.jsonb_array_elements(p -> v_list) WITH ORDINALITY AS t(e, n)
         WHERE jsonb_typeof(e) IS DISTINCT FROM 'string'
            OR CASE v_list WHEN 'agents' THEN (e #>> '{}') !~ c_agent OR length(e #>> '{}') > c_max_name + 6
                           WHEN 'runs' THEN (e #>> '{}') !~ c_uuid
                           ELSE false END
         ORDER BY n LIMIT 1;
        IF FOUND THEN
            IF length(v_bad) > c_max_shown THEN
                v_bad := left(v_bad, c_max_shown) || '...';
            END IF;
            PERFORM basalt_meta._scope_refused('SHAPE', format(CASE v_list WHEN 'agents' THEN '%s is not an agent:<name> name'
                                                                            WHEN 'runs' THEN '%s is not a run id'
                                                                            ELSE '%s is not a schema.table name' END, v_bad));
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
