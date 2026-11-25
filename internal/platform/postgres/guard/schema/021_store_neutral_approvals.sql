-- Version 10: store-neutral texts. This file: what a person signs for a
-- held write (CONTRACT.md, Approvals): the preview lines and the binding
-- name the resource, shape and store, the request by family and the agent
-- as agent:<name>, and the reveal finds a redacted line by its resource.

-- The preview lines of one action (CONTRACT.md, Approvals): one jsonb text
-- per row, cascades included, in COLLATE "C" order, in the store-neutral
-- form (CONTRACT.md, Stores): shape RECORD, store {kind, verb} with the
-- row's own op as verb, and resource. Rows of tables p_role
-- cannot SELECT are redacted to a row hash. The same function builds the
-- lines at preview and at commit, so a match means the same rows.
CREATE OR REPLACE FUNCTION basalt_meta._lines(p_change uuid, p_assigned text[], p_role name) RETURNS text[]
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce(array_agg(s.line ORDER BY s.line COLLATE "C"), '{}'::text[])
      FROM (
        SELECT CASE WHEN coalesce(has_table_privilege(p_role, l.table_oid, 'SELECT'), false)
                    THEN jsonb_build_object('op', l.op, 'key', x.key, 'old', l.old_row, 'set', x.set,
                                            'shape', 'RECORD', 'store', jsonb_build_object('kind', 'POSTGRES', 'verb', l.op),
                                            'resource', l.table_name, 'cascaded', x.cascaded)::text
                    ELSE jsonb_build_object('op', l.op, 'resource', l.table_name,
                                            'shape', 'RECORD', 'store', jsonb_build_object('kind', 'POSTGRES', 'verb', l.op),
                                            'rowHash', encode(sha256(convert_to(jsonb_build_array(x.key, l.old_row, x.set)::text, 'UTF8')), 'hex'),
                                            'cascaded', x.cascaded, 'redacted', true)::text
               END AS line
          FROM basalt_meta.ledger l
          CROSS JOIN LATERAL (SELECT coalesce((l.detail ->> 'cascaded')::boolean, false) AS cascaded) c
          CROSS JOIN LATERAL (
              SELECT CASE WHEN l.op = 'INSERT' THEN NULL ELSE l.row_key END AS key,
                     CASE WHEN l.op = 'DELETE' OR c.cascaded THEN NULL
                          ELSE coalesce((SELECT jsonb_object_agg(k, l.new_row -> k) FROM unnest(p_assigned) k), '{}'::jsonb)
                     END AS set,
                     c.cascaded
          ) x
         WHERE l.change_id = p_change AND l.kind = 'ROW_CHANGE'
      ) s
$$;

-- Agent: hold a write for the person's approval. Agent, run, task and
-- intent come from session_user and the basalt.* settings; the binding is
-- built here, so the engine cannot choose what the passkey signs beyond the
-- statement, parameters and lines, which the commit check recomputes.
-- p_op is the request's own command (INSERT, UPDATE or DELETE), the verb
-- of its APPROVAL_PENDING row; the earlier form, without it, is dropped.
DROP FUNCTION IF EXISTS basalt_meta.hold_action(text, jsonb, text[], text[]);
CREATE OR REPLACE FUNCTION basalt_meta.hold_action(p_op text, p_statement text, p_params jsonb, p_assigned text[], p_lines text[])
RETURNS TABLE (approval_id uuid, binding_text text, expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    c_hold_max constant int := 50;
    c_ttl      constant interval := interval '24 hours';
    v_intent   text := nullif(current_setting('basalt.intent', true), '');
    v_run      uuid := basalt_meta._setting_uuid('basalt.run_id');
    v_rows     int := coalesce(cardinality(p_lines), 0);
    v_id       uuid := basalt_meta._uuidv7();
    v_expires  timestamptz := now() + c_ttl;
    v_task     uuid;
    v_first    jsonb;
    v_hash     bytea;
    v_text     text;
    v_change   uuid;
    v_line     text;
    v_ok       boolean;
BEGIN
    PERFORM basalt_meta._require_agent();
    IF v_intent IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'BS001', MESSAGE = 'INTENT_REQUIRED',
            DETAIL = format('hold_action by %s without basalt.intent', session_user);
    END IF;
    PERFORM basalt_meta._check_text('basalt.intent', v_intent, 2000, true);
    IF v_run IS NULL THEN
        PERFORM basalt_meta._invalid('basalt.run_id is required: an approval belongs to a run');
    END IF;
    v_task := basalt_meta._run_task(v_run, basalt_meta._setting_uuid('basalt.task_id'));
    PERFORM basalt_meta._check_text('statement', p_statement, 65536, true);
    PERFORM basalt_meta._check_text('params', p_params::text, 65536, false);
    IF p_params IS NOT NULL AND jsonb_typeof(p_params) <> 'array' THEN
        PERFORM basalt_meta._invalid('params must be a JSON array');
    END IF;
    PERFORM basalt_meta._check_assigned(p_assigned);
    IF v_rows < 1 OR v_rows > c_hold_max THEN
        PERFORM basalt_meta._invalid(format('a held action has 1 to %s lines', c_hold_max));
    END IF;
    -- Before any line is parsed: the cap bounds the work below too.
    PERFORM basalt_meta._check_held_lines(p_lines);
    FOREACH v_line IN ARRAY p_lines LOOP
        BEGIN
            v_ok := v_line IS NOT NULL
                    AND jsonb_typeof(v_line::jsonb) = 'object' AND v_line::jsonb::text = v_line
                    AND (v_line::jsonb ->> 'op') IN ('INSERT', 'UPDATE', 'DELETE');
        EXCEPTION WHEN OTHERS THEN
            v_ok := false;
        END;
        IF NOT v_ok THEN
            PERFORM basalt_meta._invalid('each line must be the jsonb text of a preview line');
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM generate_subscripts(p_lines, 1) i
                WHERE i > 1 AND (p_lines[i - 1] COLLATE "C") > (p_lines[i] COLLATE "C")) THEN
        PERFORM basalt_meta._invalid('lines must be in COLLATE "C" order');
    END IF;
    SELECT x::jsonb INTO v_first FROM unnest(p_lines) x
     WHERE NOT coalesce((x::jsonb ->> 'cascaded')::boolean, false) LIMIT 1;
    IF v_first IS NULL THEN
        PERFORM basalt_meta._invalid('no line belongs to the statement''s own resource');
    END IF;

    v_hash := sha256(convert_to(array_to_string(p_lines, E'\n'), 'UTF8'));
    v_text := jsonb_build_object(
        'kind', 'APPROVE', 'approvalId', v_id,
        'store', jsonb_build_object('kind', 'POSTGRES', 'name', current_database()),
        'agent', basalt_meta._agent_text(session_user),
        'runId', v_run, 'taskId', v_task, 'intent', v_intent,
        'request', jsonb_build_object('kind', 'SQL', 'statement', p_statement, 'params', coalesce(p_params, '[]'::jsonb)),
        'assignedFields', to_jsonb(p_assigned),
        'rows', v_rows, 'rowsHash', encode(v_hash, 'hex'),
        'expiresAt', to_char(v_expires AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))::text;

    INSERT INTO basalt_meta.changes (tx, stmt_ts, agent, run_id, task_id, intent, op, table_name, statement, params,
                                     rows, cascaded_rows, has_delete, mode, approval_id, status)
    VALUES (pg_current_xact_id(), statement_timestamp(), session_user, v_run, v_task, v_intent,
            v_first ->> 'op', v_first ->> 'resource', p_statement, p_params, v_rows,
            (SELECT count(x) FROM unnest(p_lines) x WHERE coalesce((x::jsonb ->> 'cascaded')::boolean, false)),
            EXISTS (SELECT 1 FROM unnest(p_lines) x WHERE x::jsonb ->> 'op' = 'DELETE'),
            'APPLY', v_id, 'APPROVAL_PENDING')
    RETURNING change_id INTO v_change;

    INSERT INTO basalt_meta.approvals (approval_id, kind, agent, run_id, task_id, intent, statement, params,
                                       assigned_columns, lines, rows, rows_hash, binding_text, binding,
                                       held_change, expires_at)
    VALUES (v_id, 'APPROVE', session_user, v_run, v_task, v_intent, p_statement, p_params, p_assigned, p_lines,
            v_rows, v_hash, v_text, sha256(convert_to(v_text, 'UTF8')), v_change, v_expires);

    PERFORM basalt_meta._append_verb(session_user, v_change, 'APPROVAL_PENDING', NULL, v_first ->> 'op', NULL, NULL, NULL, NULL,
        jsonb_build_object('approvalId', v_id, 'runId', v_run, 'taskId', v_task, 'intent', v_intent,
                           'statement', p_statement, 'rows', v_rows, 'rowsHash', encode(v_hash, 'hex'),
                           'expiresAt', v_expires),
        CASE WHEN p_op IN ('INSERT', 'UPDATE', 'DELETE') THEN p_op END);
    approval_id := v_id;
    binding_text := v_text;
    expires_at := v_expires;
    RETURN NEXT;
END $$;
GRANT EXECUTE ON FUNCTION basalt_meta.hold_action(text, text, jsonb, text[], text[]) TO {{agents}};

-- Relay of the approval page's reveal, second transaction: in the PREVIEW
-- transaction that re-ran the held statement and recorded it with
-- finish_change, the values of the held approval's redacted lines.
CREATE OR REPLACE FUNCTION basalt_meta.reveal_approval_rows(p_approval_id uuid, p_ticket bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    a       basalt_meta.approvals;
    c       basalt_meta.changes;
    v_lines text[];
    v_rows  jsonb;
BEGIN
    PERFORM basalt_meta._require_agent();
    IF pg_catalog.current_setting('basalt.mode', true) IS DISTINCT FROM 'PREVIEW' THEN
        PERFORM basalt_meta._reveal_refused('APPROVAL_INVALID');
    END IF;
    -- The caller's own approval, read without a lock: the preview above
    -- already holds chain_head, and submit_approval takes the approval row
    -- before chain_head, so locking it here could deadlock with a
    -- signature. The checks are _reveal_approval_lock's.
    SELECT * INTO a FROM basalt_meta.approvals x
     WHERE x.approval_id = p_approval_id AND x.agent = session_user;
    IF NOT FOUND THEN
        PERFORM basalt_meta._approval_invalid('no such approval');
    END IF;
    IF a.used_by_change IS NOT NULL THEN
        PERFORM basalt_meta._approval_invalid('approval already used');
    END IF;
    IF a.approved_at IS NOT NULL THEN
        PERFORM basalt_meta._approval_invalid('approval already approved');
    END IF;
    IF a.expires_at <= pg_catalog.clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'APPROVAL_EXPIRED',
            DETAIL = pg_catalog.format('approval %s expired at %s', a.approval_id, a.expires_at);
    END IF;
    IF a.reveal_ticket_hash IS NULL OR pg_catalog.sha256(p_ticket) IS DISTINCT FROM a.reveal_ticket_hash
       OR a.reveal_until IS NULL OR a.reveal_until <= pg_catalog.clock_timestamp() THEN
        PERFORM basalt_meta._reveal_refused('APPROVAL_INVALID');
    END IF;
    -- The preview's change, as preview_lines finds it; its statement and
    -- parameters are the ones finish_change recorded in this transaction.
    SELECT * INTO c FROM basalt_meta.changes x
     WHERE x.tx = pg_catalog.pg_current_xact_id_if_assigned() AND x.agent = session_user AND x.mode = 'PREVIEW'
     ORDER BY x.stmt_ts DESC LIMIT 1;
    IF NOT FOUND OR c.statement IS DISTINCT FROM a.statement OR c.params IS DISTINCT FROM a.params
       OR c.run_id IS DISTINCT FROM a.run_id THEN
        PERFORM basalt_meta._reveal_refused('APPROVAL_INVALID');
    END IF;
    v_lines := basalt_meta._lines(c.change_id, a.assigned_columns, session_user);
    IF v_lines IS DISTINCT FROM a.lines THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'APPROVAL_INVALID', DETAIL = 'ROWS_CHANGED',
            HINT = 'the rows changed since the agent asked; this approval can no longer apply, and the agent must try the write again';
    END IF;
    WITH wanted AS (
        SELECT (u.n - 1)::int AS line, u.t::jsonb ->> 'rowHash' AS row_hash, u.t::jsonb ->> 'resource' AS table_name
          FROM pg_catalog.unnest(a.lines) WITH ORDINALITY u(t, n)
         WHERE (u.t::jsonb -> 'redacted') = 'true'::jsonb
    )
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('line', w.line) || m.revealed ORDER BY w.line)
      INTO v_rows
      FROM wanted w
      JOIN LATERAL (SELECT r.revealed FROM basalt_meta._reveal_lines(c.change_id, a.assigned_columns) r
                     WHERE r.table_name = w.table_name AND r.row_hash = w.row_hash
                     LIMIT 1) m ON true;
    RETURN pg_catalog.jsonb_build_object('rows', coalesce(v_rows, '[]'::jsonb));
END $$;
