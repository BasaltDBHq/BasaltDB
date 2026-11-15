-- Approvals: the WebAuthn assertion checks, holding a write, preview
-- lines, register_passkey and submit_approval.

-- The WebAuthn checks of an assertion over p_binding (the challenge), for
-- approvals and, from M3, revert authorisations. Raises BS005
-- APPROVAL_INVALID with a detail; on success bumps the passkey's counter.
CREATE FUNCTION basalt_meta._verify_assertion(
    p_binding bytea, p_credential_id bytea, p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    c_flag_up       constant int := 1;  -- user present
    c_flag_uv       constant int := 4;  -- user verified (Touch ID, Face ID)
    c_rpid_len      constant int := 32;
    c_counter_at    constant int := 34; -- 1-based offset of the 4-byte counter
    c_counter_len   constant int := 4;
    c_auth_min      constant int := 37;
    c_auth_max      constant int := 1024;
    c_client_max    constant int := 4096;
    c_signature_max constant int := 128;
    pk      basalt_meta.passkeys;
    cd      jsonb;
    flags   int;
    counter bigint;
    sig     record;
BEGIN
    IF p_binding IS NULL OR p_credential_id IS NULL OR p_authenticator_data IS NULL
       OR p_client_data_json IS NULL OR p_signature IS NULL THEN
        PERFORM basalt_meta._approval_invalid('the assertion is missing a field');
    END IF;
    IF octet_length(p_authenticator_data) > c_auth_max OR octet_length(p_client_data_json) > c_client_max
       OR octet_length(p_signature) > c_signature_max THEN
        PERFORM basalt_meta._approval_invalid('the assertion is too large');
    END IF;
    SELECT * INTO pk FROM basalt_meta.passkeys k WHERE k.credential_id = p_credential_id FOR UPDATE;
    IF NOT FOUND THEN
        PERFORM basalt_meta._approval_invalid('unknown passkey');
    END IF;
    BEGIN
        cd := convert_from(p_client_data_json, 'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
        cd := NULL;
    END;
    IF jsonb_typeof(cd) IS DISTINCT FROM 'object'
       OR cd ->> 'type' IS DISTINCT FROM 'webauthn.get'
       OR cd ->> 'challenge' IS DISTINCT FROM basalt_meta._b64url(p_binding)
       OR cd ->> 'origin' IS DISTINCT FROM pk.origin THEN
        PERFORM basalt_meta._approval_invalid('client data does not match the request');
    END IF;
    IF octet_length(p_authenticator_data) < c_auth_min
       OR substring(p_authenticator_data FROM 1 FOR c_rpid_len) <> sha256(convert_to(pk.rp_id, 'UTF8')) THEN
        PERFORM basalt_meta._approval_invalid('rpIdHash mismatch');
    END IF;
    flags := get_byte(p_authenticator_data, c_rpid_len);
    IF flags & c_flag_up = 0 OR flags & c_flag_uv = 0 THEN
        PERFORM basalt_meta._approval_invalid('user presence and verification required');
    END IF;
    counter := basalt_meta._num(substring(p_authenticator_data FROM c_counter_at FOR c_counter_len));
    -- Some authenticators never count: 0 is accepted while the stored count is 0.
    IF (counter <> 0 OR pk.sign_count <> 0) AND counter <= pk.sign_count THEN
        PERFORM basalt_meta._approval_invalid('signature counter did not increase (cloned authenticator or replay)');
    END IF;
    sig := basalt_meta._der_sig(p_signature);
    IF NOT basalt_meta._p256_verify(sha256(p_authenticator_data || sha256(p_client_data_json)),
                                    sig.r, sig.s, basalt_meta._num(pk.public_key_x), basalt_meta._num(pk.public_key_y)) THEN
        PERFORM basalt_meta._approval_invalid('bad passkey signature');
    END IF;
    UPDATE basalt_meta.passkeys k SET sign_count = counter WHERE k.credential_id = pk.credential_id;
END $$;

-- Admin only (basalt init): store the person's passkey. Not granted to
-- agents.
CREATE FUNCTION basalt_meta.register_passkey(
    p_credential_id bytea, p_x bytea, p_y bytea, p_rp_id text, p_origin text, p_label text
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF p_credential_id IS NULL OR octet_length(p_credential_id) NOT BETWEEN 1 AND 1023 THEN
        PERFORM basalt_meta._invalid('credential id must be 1 to 1023 bytes');
    END IF;
    IF octet_length(p_x) IS DISTINCT FROM 32 OR octet_length(p_y) IS DISTINCT FROM 32
       OR NOT basalt_meta._p256_on_curve(basalt_meta._num(p_x), basalt_meta._num(p_y)) THEN
        PERFORM basalt_meta._invalid('the public key is not a P-256 point');
    END IF;
    PERFORM basalt_meta._check_text('rp_id', p_rp_id, 253, true);
    PERFORM basalt_meta._check_text('origin', p_origin, 300, true);
    PERFORM basalt_meta._check_text('label', p_label, 200, true);
    INSERT INTO basalt_meta.passkeys (credential_id, public_key_x, public_key_y, rp_id, origin, label)
    VALUES (p_credential_id, p_x, p_y, p_rp_id, p_origin, p_label)
    ON CONFLICT (credential_id) DO UPDATE
       SET public_key_x = excluded.public_key_x, public_key_y = excluded.public_key_y,
           rp_id = excluded.rp_id, origin = excluded.origin, label = excluded.label, sign_count = 0;
END $$;

-- The preview lines of one action (CONTRACT.md, Approvals): one jsonb text
-- per row, cascades included, in COLLATE "C" order. Rows of tables p_role
-- cannot SELECT are redacted to a row hash. The same function builds the
-- lines at preview and at commit, so a match means the same rows.
CREATE FUNCTION basalt_meta._lines(p_change uuid, p_assigned text[], p_role name) RETURNS text[]
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT coalesce(array_agg(s.line ORDER BY s.line COLLATE "C"), '{}'::text[])
      FROM (
        SELECT CASE WHEN coalesce(has_table_privilege(p_role, l.table_oid, 'SELECT'), false)
                    THEN jsonb_build_object('op', l.op, 'key', x.key, 'old', l.old_row, 'set', x.set,
                                            'table', l.table_name, 'cascaded', x.cascaded)::text
                    ELSE jsonb_build_object('op', l.op, 'table', l.table_name,
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

CREATE FUNCTION basalt_meta._check_assigned(p_assigned text[]) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog AS $$
DECLARE
    c_max_columns constant int := 1600;  -- Postgres's column limit
    c_ident_max   constant int := 63;    -- NAMEDATALEN - 1
BEGIN
    IF p_assigned IS NULL OR cardinality(p_assigned) > c_max_columns
       OR EXISTS (SELECT 1 FROM unnest(p_assigned) k WHERE coalesce(k, '') = '' OR octet_length(k) > c_ident_max)
       OR (SELECT count(DISTINCT k) FROM unnest(p_assigned) k) <> cardinality(p_assigned) THEN
        PERFORM basalt_meta._invalid('assigned columns must be distinct column names');
    END IF;
END $$;

-- Agent, in a PREVIEW transaction after the statement: the action's lines.
CREATE FUNCTION basalt_meta.preview_lines(p_assigned text[]) RETURNS SETOF text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_change uuid;
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
    RETURN QUERY SELECT u.line FROM unnest(basalt_meta._lines(v_change, p_assigned, session_user)) WITH ORDINALITY u(line, n)
                  ORDER BY u.n;
END $$;

-- Agent: hold a write for the person's approval. Agent, run, task and
-- intent come from session_user and the basalt.* settings; the binding is
-- built here, so the engine cannot choose what the passkey signs beyond the
-- statement, parameters and lines, which the commit check recomputes.
CREATE FUNCTION basalt_meta.hold_action(p_statement text, p_params jsonb, p_assigned text[], p_lines text[])
RETURNS TABLE (approval_id uuid, binding_text text, expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
#variable_conflict use_column
DECLARE
    c_hold_max constant int := 50;
    c_line_max constant int := 65536;
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
    FOREACH v_line IN ARRAY p_lines LOOP
        BEGIN
            v_ok := v_line IS NOT NULL AND octet_length(v_line) <= c_line_max
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

-- Any relay (the engine for the agent, basalt approve): the person's
-- passkey assertion over the approval's binding. The relay is untrusted;
-- only a valid signature counts.
CREATE FUNCTION basalt_meta.submit_approval(
    p_approval_id uuid, p_credential_id bytea, p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea
) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    a    basalt_meta.approvals;
    v_at timestamptz := now();
BEGIN
    PERFORM basalt_meta._require_agent();
    SELECT * INTO a FROM basalt_meta.approvals x WHERE x.approval_id = p_approval_id FOR UPDATE;
    IF NOT FOUND THEN
        PERFORM basalt_meta._approval_invalid('no such approval');
    END IF;
    IF a.used_by_change IS NOT NULL THEN
        PERFORM basalt_meta._approval_invalid('approval already used');
    END IF;
    IF a.approved_at IS NOT NULL THEN
        PERFORM basalt_meta._approval_invalid('approval already signed');
    END IF;
    IF a.expires_at <= now() THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'APPROVAL_EXPIRED',
            DETAIL = format('approval %s expired at %s', a.approval_id, a.expires_at);
    END IF;
    PERFORM basalt_meta._verify_assertion(a.binding, p_credential_id, p_authenticator_data, p_client_data_json, p_signature);
    UPDATE basalt_meta.approvals x SET approved_at = v_at, credential_id = p_credential_id
     WHERE x.approval_id = a.approval_id;
    PERFORM basalt_meta._append(a.agent, a.held_change, 'APPROVED', NULL, NULL, NULL, NULL, NULL, NULL,
        jsonb_build_object('approvalId', a.approval_id, 'credentialId', encode(p_credential_id, 'hex'),
                           'relayedBy', session_user));
    RETURN v_at;
END $$;

-- Row trigger: an approval named by basalt.approval_id must be this
-- agent's, for this run, signed, unused and unexpired.
CREATE FUNCTION basalt_meta._check_approval(p_id uuid, p_run uuid) RETURNS basalt_meta.approvals
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    a basalt_meta.approvals;
BEGIN
    SELECT * INTO a FROM basalt_meta.approvals x WHERE x.approval_id = p_id;
    IF NOT FOUND THEN
        PERFORM basalt_meta._approval_invalid('no such approval');
    END IF;
    IF a.agent <> session_user THEN
        PERFORM basalt_meta._approval_invalid('approval is for another agent');
    END IF;
    IF a.run_id IS DISTINCT FROM p_run THEN
        PERFORM basalt_meta._approval_invalid('approval is for another run');
    END IF;
    IF a.used_by_change IS NOT NULL THEN
        PERFORM basalt_meta._approval_invalid('approval already used');
    END IF;
    IF a.expires_at <= now() THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'APPROVAL_EXPIRED',
            DETAIL = format('approval %s expired at %s', a.approval_id, a.expires_at);
    END IF;
    IF a.approved_at IS NULL THEN
        PERFORM basalt_meta._approval_invalid('not approved yet: the person has not signed it with their passkey');
    END IF;
    RETURN a;
END $$;

-- At commit: the applied action is the one the person approved. Checked
-- once per change (later deferred events of the same change see it used
-- by this change). The held record is replaced by the applied one.
CREATE FUNCTION basalt_meta._commit_approval(c basalt_meta.changes) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    a       basalt_meta.approvals;
    v_lines text[];
BEGIN
    SELECT * INTO a FROM basalt_meta.approvals x WHERE x.approval_id = c.approval_id FOR UPDATE;
    IF NOT FOUND THEN
        PERFORM basalt_meta._approval_invalid('no such approval');
    END IF;
    IF a.used_by_change = c.change_id THEN
        RETURN;
    END IF;
    IF a.used_by_change IS NOT NULL THEN
        PERFORM basalt_meta._approval_invalid('approval already used');
    END IF;
    IF a.agent <> c.agent OR a.run_id IS DISTINCT FROM c.run_id OR a.approved_at IS NULL THEN
        PERFORM basalt_meta._approval_invalid('approval is not signed for this agent and run');
    END IF;
    IF a.expires_at <= now() THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'APPROVAL_EXPIRED',
            DETAIL = format('approval %s expired at %s', a.approval_id, a.expires_at);
    END IF;
    IF c.statement IS DISTINCT FROM a.statement OR c.params IS DISTINCT FROM a.params THEN
        PERFORM basalt_meta._approval_invalid('the statement or its parameters differ from the approval');
    END IF;
    v_lines := basalt_meta._lines(c.change_id, a.assigned_columns, a.agent);
    IF cardinality(v_lines) <> a.rows
       OR sha256(convert_to(array_to_string(v_lines, E'\n'), 'UTF8')) <> a.rows_hash THEN
        PERFORM basalt_meta._approval_invalid('rows changed since the preview; a fresh preview and approval are needed');
    END IF;
    UPDATE basalt_meta.approvals x SET used_by_change = c.change_id WHERE x.approval_id = a.approval_id;
    DELETE FROM basalt_meta.changes x WHERE x.change_id = a.held_change AND x.status = 'APPROVAL_PENDING';
END $$;
