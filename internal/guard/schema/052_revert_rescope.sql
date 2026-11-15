-- Rescoping a revert: rescope_revert, reset_revert and the widen proof.

-- base64url (no padding) to bytes, NULL when t is not base64url.
CREATE OR REPLACE FUNCTION basalt_meta._b64url_decode(t text) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
    SELECT CASE WHEN t ~ '^[A-Za-z0-9_-]*$' AND length(t) % 4 <> 1
                THEN decode(rpad(translate(t, '-_', '+/'), (length(t) + 3) / 4 * 4, '='), 'base64') END
$$;

-- The one answer to every failed proof or token check of rescope_revert
-- (CONTRACT.md, Rescope, widen and reject, check order step 3): whatever
-- failed, the caller learns nothing about other agents' work.
CREATE OR REPLACE FUNCTION basalt_meta._widen_refused() RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'REVERT_INVALID', DETAIL = 'WIDEN_REFUSED',
        HINT = 'a scope beyond the requesting agent''s own work, and any scope change after the person widened it, needs the person on the revert page';
END $$;

-- The caller's own revert p_revert_id, locked, while its scope may still
-- change: not applied, rejected, signed or expired. Another role's revert
-- reads like one that does not exist.
CREATE OR REPLACE FUNCTION basalt_meta._revert_lock_pending(p_revert_id uuid) RETURNS basalt_meta.reverts
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    r basalt_meta.reverts;
BEGIN
    SELECT * INTO r FROM basalt_meta.reverts x
     WHERE x.revert_id = p_revert_id AND x.requested_by = session_user FOR UPDATE;
    IF NOT FOUND THEN
        PERFORM basalt_meta._revert_invalid('no such revert');
    END IF;
    IF r.applied_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_invalid('revert already applied');
    END IF;
    IF r.rejected_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_invalid('the person rejected this revert; nothing was reverted');
    END IF;
    IF r.signed_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_invalid('revert already signed; its scope can no longer change');
    END IF;
    IF r.expires_at <= now() THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'REVERT_EXPIRED',
            DETAIL = format('revert %s expired at %s; prepare it again', r.revert_id, r.expires_at);
    END IF;
    RETURN r;
END $$;

-- True when p_proof is the person's widen proof for revert r and select
-- p_sel with key p_key: a passkey assertion, checked as submit_approval's
-- (_verify_assertion), over sha256("basalt-rescope.1\n" + revertId + "\n"
-- + base64url(nonce) + "\n" + hex(sha256(key)) + "\n" + select text).
-- Never raises for a bad proof: any error of the check (WHEN OTHERS; a
-- cancel still raises) is a bad proof, so every failure reads the same.
CREATE OR REPLACE FUNCTION basalt_meta._rescope_proven(r basalt_meta.reverts, p_sel jsonb, p_proof jsonb, p_key bytea) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    c_key_len constant int := 32; -- HKDF-SHA-256 output, CONTRACT.md
    v_challenge bytea;
BEGIN
    IF octet_length(p_key) IS DISTINCT FROM c_key_len OR jsonb_typeof(p_proof) IS DISTINCT FROM 'object' THEN
        RETURN false;
    END IF;
    v_challenge := sha256(convert_to(concat_ws(E'\n', 'basalt-rescope.1', r.revert_id::text,
        basalt_meta._b64url(r.rescope_nonce), encode(sha256(p_key), 'hex'), p_sel::text), 'UTF8'));
    BEGIN
        PERFORM basalt_meta._verify_assertion(v_challenge,
            basalt_meta._b64url_decode(p_proof ->> 'credentialId'),
            basalt_meta._b64url_decode(p_proof ->> 'authenticatorData'),
            basalt_meta._b64url_decode(p_proof ->> 'clientDataJson'),
            basalt_meta._b64url_decode(p_proof ->> 'signature'));
    EXCEPTION WHEN OTHERS THEN
        RETURN false;
    END;
    RETURN true;
END $$;

-- True when the normalized select p_sel lies inside the ceiling: the same
-- scope, and agents, runs and tables each a subset of the ceiling's (any,
-- when the ceiling's is null).
CREATE OR REPLACE FUNCTION basalt_meta._revert_select_within(p_sel jsonb, p_ceiling jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
    SELECT p_sel ->> 'scope' = p_ceiling ->> 'scope' AND p_sel ->> 'scopeId' = p_ceiling ->> 'scopeId'
       AND NOT EXISTS (SELECT 1 FROM unnest(ARRAY['agents', 'runs', 'tables']) k
                        WHERE jsonb_typeof(p_ceiling -> k) = 'array'
                          AND (jsonb_typeof(p_sel -> k) IS DISTINCT FROM 'array' OR NOT (p_ceiling -> k) @> (p_sel -> k)))
$$;

-- Scope membership (check order step 4), reached only by the requesting
-- role about its own work or by a proven or token-bearing call. The scope
-- is the proposal's, or the run or task the proposal's change or run
-- belongs to; each listed agent other than p_role has a change in it
-- (DESCRIPTOR); each listed run is a run of the task by a selected agent
-- and each listed table was written in it by them (FILTER).
CREATE OR REPLACE FUNCTION basalt_meta._revert_select_members(p_sel jsonb, p_proposed jsonb, p_role name) RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_id       uuid := (p_sel ->> 'scopeId')::uuid;
    v_prop_id  uuid := (p_proposed ->> 'scopeId')::uuid;
    v_all      jsonb := p_sel || jsonb_build_object('agents', NULL, 'runs', NULL, 'tables', NULL);
    v_refused  text[];
BEGIN
    IF NOT (p_sel ->> 'scope' = p_proposed ->> 'scope' AND v_id = v_prop_id
            OR p_sel ->> 'scope' = 'TASK' AND p_proposed ->> 'scope' = 'RUN'
               AND EXISTS (SELECT 1 FROM basalt_meta.runs r WHERE r.run_id = v_prop_id AND r.task_id = v_id)
            OR p_sel ->> 'scope' = 'TASK' AND p_proposed ->> 'scope' = 'CHANGE'
               AND EXISTS (SELECT 1 FROM basalt_meta.changes c WHERE c.change_id = v_prop_id AND c.task_id = v_id)
            OR p_sel ->> 'scope' = 'RUN' AND p_proposed ->> 'scope' = 'CHANGE'
               AND EXISTS (SELECT 1 FROM basalt_meta.changes c WHERE c.change_id = v_prop_id AND c.run_id = v_id)) THEN
        PERFORM basalt_meta._scope_refused('DESCRIPTOR',
            'the scope is the proposal''s change, run or task, or the run or task the proposal belongs to');
    END IF;
    v_refused := ARRAY(
        SELECT format('agent %s has no change in this scope', u.a)
          FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(p_sel -> 'agents') = 'array' THEN p_sel -> 'agents' ELSE '[]' END) u(a)
         WHERE u.a <> p_role::text
           AND NOT EXISTS (SELECT 1 FROM basalt_meta._revert_scope(v_all) s WHERE s.agent::text = u.a));
    IF cardinality(v_refused) > 0 THEN
        PERFORM basalt_meta._scope_refused('DESCRIPTOR', array_to_string(v_refused, '; '));
    END IF;
    v_refused := ARRAY(
        SELECT format('run %s is not a run in task %s', u.run, v_id)
          FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(p_sel -> 'runs') = 'array' THEN p_sel -> 'runs' ELSE '[]' END) u(run)
         WHERE NOT EXISTS (SELECT 1 FROM basalt_meta.runs r
                            WHERE r.run_id = u.run::uuid AND r.task_id = v_id
                              AND (jsonb_typeof(p_sel -> 'agents') IS DISTINCT FROM 'array' OR (p_sel -> 'agents') ? r.agent::text))
        UNION ALL
        SELECT format('%s has no change in this scope', u.tbl)
          FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(p_sel -> 'tables') = 'array' THEN p_sel -> 'tables' ELSE '[]' END) u(tbl)
         WHERE NOT EXISTS (SELECT 1 FROM basalt_meta._revert_rows(p_sel || jsonb_build_object('tables', NULL)) x
                            WHERE x.table_name = u.tbl));
    IF cardinality(v_refused) > 0 THEN
        PERFORM basalt_meta._scope_refused('FILTER', array_to_string(v_refused, '; '));
    END IF;
END $$;

-- What the person may pick from inside the select they proved (CONTRACT.md,
-- revert-scope-response.schema.json): the agents with changes in it, their
-- runs and the tables written. Returned only to a proven or token-bearing
-- rescope_revert call; no view holds it.
CREATE OR REPLACE FUNCTION basalt_meta._revert_catalog(p_sel jsonb) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    WITH s AS (SELECT c.change_id, c.agent, c.run_id FROM basalt_meta._revert_scope(p_sel) x
                 JOIN basalt_meta.changes c ON c.change_id = x.change_id)
    SELECT jsonb_build_object(
        'agents', coalesce((SELECT jsonb_agg(jsonb_build_object('agent', a.agent, 'changes', a.n) ORDER BY a.agent::text COLLATE "C")
                              FROM (SELECT s.agent, count(s.change_id)::int AS n FROM s GROUP BY s.agent) a), '[]'::jsonb),
        'runs', coalesce((SELECT jsonb_agg(jsonb_build_object(
                                     'runId', u.run_id, 'agent', u.agent, 'changes', u.n,
                                     'startedAt', to_char(r.started_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
                                 ORDER BY u.run_id)
                            FROM (SELECT s.run_id, s.agent, count(s.change_id)::int AS n FROM s
                                   WHERE s.run_id IS NOT NULL GROUP BY s.run_id, s.agent) u
                            JOIN basalt_meta.runs r ON r.run_id = u.run_id), '[]'::jsonb),
        'tables', coalesce((SELECT jsonb_agg(jsonb_build_object('table', t.table_name, 'rows', t.n) ORDER BY t.table_name COLLATE "C")
                              FROM (SELECT x.table_name, count(x.seq)::int AS n FROM basalt_meta._revert_rows(p_sel) x
                                     GROUP BY x.table_name) t), '[]'::jsonb))
$$;

-- Rebuild pending revert r for the normalized select p_sel, as
-- prepare_revert builds a new one: the trial run, the lines for the
-- requesting role, totals, rowsHash, a large plan's numbered lines and
-- sample, the binding (with r's proposal) and a fresh one-hour expiry. A
-- TASK with no line is stored empty (the page disables signing); any other
-- scope with nothing to restore is NOTHING_TO_REVERT. Returns the row.
CREATE OR REPLACE FUNCTION basalt_meta._revert_rebuild(r basalt_meta.reverts, p_sel jsonb) RETURNS basalt_meta.reverts
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    c_ttl       constant interval := interval '1 hour';
    c_max_lines constant int := 1000; -- one-call revert and lines in a link (M3-9, N12-4, RSS-1)
    v_expires   timestamptz := now() + c_ttl;
    v_chains    basalt_meta.revert_chain[];
    v_items     basalt_meta.revert_item[];
    v_lines     text[];
    v_sample    text[];
    v_rows      int;
    v_hash      bytea;
    v_sample_h  bytea;
    v_batched   boolean;
    v_text      text;
    v_out       basalt_meta.reverts;
BEGIN
    v_chains := basalt_meta._revert_chain_list(p_sel, p_sel ->> 'scope' = 'TASK');
    v_items := basalt_meta._revert_trial_items(ARRAY(SELECT basalt_meta._revert_item(x, false) FROM unnest(v_chains) x));
    v_lines := basalt_meta._revert_text(v_items, r.requested_by);
    SELECT count(x.table_oid)::int INTO v_rows FROM unnest(v_items) x WHERE x.conflict IS NULL;
    IF v_rows = 0 AND cardinality(v_lines) > 0 THEN
        RAISE EXCEPTION USING ERRCODE = 'BS009', MESSAGE = 'NOTHING_TO_REVERT',
            DETAIL = format('every row of %s %s would be skipped', p_sel ->> 'scope', p_sel ->> 'scopeId');
    END IF;
    v_hash := sha256(convert_to(array_to_string(v_lines, E'\n'), 'UTF8'));
    v_batched := cardinality(v_lines) > c_max_lines;
    v_sample := v_lines;
    IF v_batched THEN
        v_sample := basalt_meta._revert_sample(v_lines, c_max_lines);
        v_sample_h := sha256(convert_to(array_to_string(v_sample, E'\n'), 'UTF8'));
    END IF;
    v_text := basalt_meta._revert_binding(r.revert_id, p_sel, r.proposed, r.requested_by, r.intent, v_rows,
                                          cardinality(v_lines) - v_rows, v_hash, v_expires, v_sample_h,
                                          basalt_meta._revert_agent_rows(v_items));
    DELETE FROM basalt_meta.revert_lines l WHERE l.revert_id = r.revert_id;
    UPDATE basalt_meta.reverts x
       SET selection = p_sel, lines = v_sample, rows = v_rows, skipped = cardinality(v_lines) - v_rows,
           rows_hash = v_hash, binding_text = v_text, binding = sha256(convert_to(v_text, 'UTF8')),
           expires_at = v_expires, batched = v_batched, sample_hash = v_sample_h,
           covered = (SELECT array_agg(s ORDER BY s) FROM basalt_meta._revert_covered(p_sel) s)
     WHERE x.revert_id = r.revert_id
    RETURNING x.* INTO v_out;
    IF v_batched THEN
        -- Execution order, as prepare_revert: the writes that landed on
        -- trial in the order they landed, then the lines the trial skipped.
        INSERT INTO basalt_meta.revert_lines (revert_id, line_no, line, chain)
        SELECT r.revert_id, row_number() OVER (ORDER BY it.step NULLS LAST, it.first_seq),
               basalt_meta._revert_line(it, r.requested_by), ch
          FROM unnest(v_items) it JOIN unnest(v_chains) ch ON ch.first_seq = it.first_seq;
    END IF;
    RETURN v_out;
END $$;

-- What rescope_revert and reset_revert return for revert r: the request
-- the page checks, and the nonce a widen proof signs next.
CREATE OR REPLACE FUNCTION basalt_meta._revert_rescoped(r basalt_meta.reverts) RETURNS jsonb
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
    SELECT jsonb_build_object('revertId', r.revert_id, 'binding', r.binding_text, 'expiresAt', r.expires_at,
                              'lines', to_jsonb(coalesce(r.lines, '{}'::text[])),
                              'rescopeNonce', basalt_meta._b64url(r.rescope_nonce))
$$;

-- Agent, for the engine's scope route (CONTRACT.md, Rescope, widen and
-- reject): change the scope of the caller's own pending revert. In this
-- order, stopping at the first failure:
--   1. shape, from p_select alone (BS011 SHAPE, STORE_RESERVED, FILTER_CAP);
--   2. own work: a yes or no that raises nothing;
--   3. a proof (p_proof and p_rescope_key, against the current nonce, which
--      it replaces), or, while nobody widened the revert, own work, or the
--      scope token p_token with the select inside the ceiling; every
--      failure is REVERT_INVALID WIDEN_REFUSED;
--   4. scope membership (BS011 DESCRIPTOR, FILTER).
-- Then the lines are rebuilt and REVERT_RESCOPED is appended with the path
-- (via). A proven call sets the ceiling and returns a new scope token
-- (only its hash is kept); a proven or token-bearing call also gets the
-- catalog. The link secret never reaches Postgres: only the key the engine
-- derived from it, of which only sha256 is recorded.
CREATE OR REPLACE FUNCTION basalt_meta.rescope_revert(
    p_revert_id uuid, p_select jsonb, p_proof jsonb, p_rescope_key bytea, p_token bytea
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    r       basalt_meta.reverts;
    v_sel   jsonb;
    v_via   text;
    v_token bytea;
    v_out   basalt_meta.reverts;
BEGIN
    PERFORM basalt_meta._require_agent();
    v_sel := basalt_meta._revert_select_norm(p_select);
    r := basalt_meta._revert_lock_pending(p_revert_id);
    CASE
    WHEN p_proof IS NOT NULL THEN
        IF NOT basalt_meta._rescope_proven(r, v_sel, p_proof, p_rescope_key) THEN
            PERFORM basalt_meta._widen_refused();
        END IF;
        v_via := 'PROOF';
    WHEN r.ceiling IS NULL AND basalt_meta._revert_own_refusal(v_sel, r.requested_by) IS NULL THEN
        v_via := 'OWN_WORK';
    WHEN r.ceiling IS NOT NULL AND p_token IS NOT NULL AND sha256(p_token) = r.scope_token_hash
         AND basalt_meta._revert_select_within(v_sel, r.ceiling) THEN
        v_via := 'SCOPE_TOKEN';
    ELSE
        PERFORM basalt_meta._widen_refused();
    END CASE;
    PERFORM basalt_meta._revert_select_members(v_sel, r.proposed, r.requested_by);

    v_out := basalt_meta._revert_rebuild(r, v_sel);
    IF v_via = 'PROOF' THEN
        v_token := basalt_meta._revert_nonce();
        UPDATE basalt_meta.reverts x
           SET ceiling = v_sel, scope_token_hash = sha256(v_token), rescope_nonce = basalt_meta._revert_nonce()
         WHERE x.revert_id = r.revert_id;
    END IF;
    UPDATE basalt_meta.reverts x SET rescoped = x.rescoped + 1 WHERE x.revert_id = r.revert_id
    RETURNING x.* INTO v_out;
    PERFORM basalt_meta._append(session_user, NULL, 'REVERT_RESCOPED', NULL, NULL, NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', r.revert_id, 'oldSelect', r.selection, 'select', v_sel,
                           'oldRowsHash', encode(r.rows_hash, 'hex'), 'rowsHash', encode(v_out.rows_hash, 'hex'),
                           'via', v_via)
        || CASE WHEN v_via = 'PROOF'
                THEN jsonb_build_object('credentialId', encode(basalt_meta._b64url_decode(p_proof ->> 'credentialId'), 'hex'),
                                        'rescopeKeyHash', encode(sha256(p_rescope_key), 'hex'))
                ELSE '{}'::jsonb END);
    RETURN basalt_meta._revert_rescoped(v_out)
        || CASE WHEN v_via = 'OWN_WORK' THEN '{}'::jsonb
                ELSE jsonb_build_object('catalog', basalt_meta._revert_catalog(v_out.ceiling)) END
        || CASE WHEN v_via = 'PROOF' THEN jsonb_build_object('scopeToken', basalt_meta._b64url(v_token))
                ELSE '{}'::jsonb END;
END $$;

-- Agent, for its reissueLink on a widened revert (owner, Q8): put the
-- caller's own pending revert back to its proposal. The lines are rebuilt,
-- the ceiling and scope token cleared, a new nonce set, and REVERT_RESET
-- appended with the select it dropped. It only ever narrows to the agent's
-- own work, so it needs no token.
CREATE OR REPLACE FUNCTION basalt_meta.reset_revert(p_revert_id uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    r     basalt_meta.reverts;
    v_out basalt_meta.reverts;
BEGIN
    PERFORM basalt_meta._require_agent();
    r := basalt_meta._revert_lock_pending(p_revert_id);
    PERFORM basalt_meta._revert_rebuild(r, r.proposed);
    UPDATE basalt_meta.reverts x
       SET ceiling = NULL, scope_token_hash = NULL, rescope_nonce = basalt_meta._revert_nonce()
     WHERE x.revert_id = r.revert_id
    RETURNING x.* INTO v_out;
    PERFORM basalt_meta._append(session_user, NULL, 'REVERT_RESET', NULL, NULL, NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', r.revert_id, 'droppedSelect', r.selection,
                           'oldRowsHash', encode(r.rows_hash, 'hex'), 'rowsHash', encode(v_out.rows_hash, 'hex')));
    RETURN basalt_meta._revert_rescoped(v_out);
END $$;
