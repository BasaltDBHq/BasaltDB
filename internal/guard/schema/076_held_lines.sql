-- Version 37: a held write keeps preview lines over 64 KiB (CONTRACT.md,
-- basalt_meta "Version 37", and Large values). Up to version 36
-- hold_action refused any line over 64 KiB with BS008, so a held DELETE of
-- a row with a large value was never held and the agent got INTERNAL,
-- though the large-values rules promise it can be approved.
--
--   - hold_action drops the per-line cap. The lines together hold at most
--     64 MiB of text (MaxHeldLinesBytes), well under Postgres's 1 GB
--     limits on a value, an array and a protocol message, and over the
--     contract's own example (a row with two 15 MB values, escaped).
--   - preview_lines checks the same cap before it returns a line, so the
--     engine never reads more than it could hold.
--   - Over the cap both refuse with BS007 NOT_ALLOWED, detail
--     HOLD_TOO_LARGE and a hint with the size: a refusal of the agent's
--     write, not invalid ledger input.
--
-- The functions are replaced with their latest version (version 4)
-- otherwise unchanged, attributes restated (CREATE OR REPLACE resets what
-- it does not name; owner and grants are kept). Non-breaking: on an older
-- guard the engine refuses a line over 64 KiB itself (HOLD_TOO_LARGE)
-- before hold_action would. Idempotent.

-- The cap on a held write's preview lines: their text summed, in bytes.
CREATE OR REPLACE FUNCTION basalt_meta._check_held_lines(p_lines text[]) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_lines_max constant bigint := 67108864;  -- 64 MiB, guard.MaxHeldLinesBytes
    v_bytes     bigint;
BEGIN
    SELECT coalesce(sum(octet_length(l)), 0) INTO v_bytes FROM unnest(p_lines) l;
    IF v_bytes > c_lines_max THEN
        RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED', DETAIL = 'HOLD_TOO_LARGE',
            HINT = format('the preview lines are %s bytes; a held write holds at most %s', v_bytes, c_lines_max);
    END IF;
END $$;
REVOKE ALL ON FUNCTION basalt_meta._check_held_lines(text[]) FROM PUBLIC;

-- Agent, in a PREVIEW transaction after the statement: the action's lines,
-- refused whole when they are over the cap.
CREATE OR REPLACE FUNCTION basalt_meta.preview_lines(p_assigned text[]) RETURNS SETOF text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_change uuid;
    v_lines  text[];
BEGIN
    PERFORM basalt_meta._require_agent();
    PERFORM basalt_meta._check_assigned(p_assigned);
    IF current_setting('basalt.mode', true) IS DISTINCT FROM 'PREVIEW' THEN
        RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED', DETAIL = 'preview_lines needs basalt.mode = PREVIEW';
    END IF;
    SELECT x.change_id INTO v_change FROM basalt_meta.changes x
     WHERE x.tx = pg_current_xact_id_if_assigned() AND x.agent = session_user AND x.mode = 'PREVIEW'
     ORDER BY x.stmt_ts DESC LIMIT 1;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    v_lines := basalt_meta._lines(v_change, p_assigned, session_user);
    PERFORM basalt_meta._check_held_lines(v_lines);
    RETURN QUERY SELECT u.line FROM unnest(v_lines) WITH ORDINALITY u(line, n) ORDER BY u.n;
END $$;

-- Agent: hold a write for the person's approval. Agent, run, task and
-- intent come from session_user and the basalt.* settings; the binding is
-- built here, so the engine cannot choose what the passkey signs beyond the
-- statement, parameters and lines, which the commit check recomputes.
CREATE OR REPLACE FUNCTION basalt_meta.hold_action(p_statement text, p_params jsonb, p_assigned text[], p_lines text[])
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
        PERFORM basalt_meta._invalid('no line belongs to the statement''s own table');
    END IF;

    v_hash := sha256(convert_to(array_to_string(p_lines, E'\n'), 'UTF8'));
    v_text := jsonb_build_object(
        'kind', 'APPROVE', 'approvalId', v_id, 'database', current_database(), 'agent', session_user,
        'runId', v_run, 'taskId', v_task, 'intent', v_intent, 'statement', p_statement,
        'params', coalesce(p_params, '[]'::jsonb), 'assignedColumns', to_jsonb(p_assigned),
        'rows', v_rows, 'rowsHash', encode(v_hash, 'hex'),
        'expiresAt', to_char(v_expires AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))::text;

    INSERT INTO basalt_meta.changes (tx, stmt_ts, agent, run_id, task_id, intent, op, table_name, statement, params,
                                     rows, cascaded_rows, has_delete, mode, approval_id, status)
    VALUES (pg_current_xact_id(), statement_timestamp(), session_user, v_run, v_task, v_intent,
            v_first ->> 'op', v_first ->> 'table', p_statement, p_params, v_rows,
            (SELECT count(x) FROM unnest(p_lines) x WHERE coalesce((x::jsonb ->> 'cascaded')::boolean, false)),
            EXISTS (SELECT 1 FROM unnest(p_lines) x WHERE x::jsonb ->> 'op' = 'DELETE'),
            'APPLY', v_id, 'APPROVAL_PENDING')
    RETURNING change_id INTO v_change;

    INSERT INTO basalt_meta.approvals (approval_id, kind, agent, run_id, task_id, intent, statement, params,
                                       assigned_columns, lines, rows, rows_hash, binding_text, binding,
                                       held_change, expires_at)
    VALUES (v_id, 'APPROVE', session_user, v_run, v_task, v_intent, p_statement, p_params, p_assigned, p_lines,
            v_rows, v_hash, v_text, sha256(convert_to(v_text, 'UTF8')), v_change, v_expires);

    PERFORM basalt_meta._append(session_user, v_change, 'APPROVAL_PENDING', NULL, v_first ->> 'op', NULL, NULL, NULL, NULL,
        jsonb_build_object('approvalId', v_id, 'runId', v_run, 'taskId', v_task, 'intent', v_intent,
                           'statement', p_statement, 'rows', v_rows, 'rowsHash', encode(v_hash, 'hex'),
                           'expiresAt', v_expires));
    approval_id := v_id;
    binding_text := v_text;
    expires_at := v_expires;
    RETURN NEXT;
END $$;
