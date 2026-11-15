-- prepare_revert for plans of any size.

-- Agent, as the CLI's relay (version 6): store a revert for the person to
-- sign. Up to 1000 lines it is applied in one call. Above, it is a batched
-- plan: every line is stored, numbered in execution order, and the binding
-- adds batched and sampleHash over the lines the link carries (the first
-- 1000, SKIP lines first; decision N12-4). rowsHash covers every line.
CREATE OR REPLACE FUNCTION basalt_meta.prepare_revert(p_scope text, p_scope_id uuid, p_intent text)
RETURNS TABLE (revert_id uuid, binding_text text, expires_at timestamptz, lines text[])
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
#variable_conflict use_column
DECLARE
    c_ttl       constant interval := interval '1 hour';
    c_max_lines constant int := 1000; -- one-call revert and lines in a link (M3-9, N12-4)
    v_id        uuid := basalt_meta._uuidv7();
    v_expires   timestamptz := now() + c_ttl;
    v_chains    basalt_meta.revert_chain[];
    v_items     basalt_meta.revert_item[];
    v_lines     text[];
    v_sample    text[];
    v_rows      int;
    v_agents    name[];
    v_covered   uuid[];
    v_hash      bytea;
    v_sample_h  bytea;
    v_batched   boolean;
    v_text      text;
BEGIN
    PERFORM basalt_meta._require_agent();
    PERFORM basalt_meta._check_text('intent', p_intent, 2000, true);
    v_chains := basalt_meta._revert_chain_list(p_scope, p_scope_id);
    v_items := basalt_meta._revert_trial_items(ARRAY(SELECT basalt_meta._revert_item(x, false) FROM unnest(v_chains) x));
    v_lines := basalt_meta._revert_text(v_items, session_user);
    SELECT count(x.table_oid)::int INTO v_rows FROM unnest(v_items) x WHERE x.conflict IS NULL;
    IF v_rows = 0 THEN
        RAISE EXCEPTION USING ERRCODE = 'BS009', MESSAGE = 'NOTHING_TO_REVERT',
            DETAIL = format('every row of %s %s would be skipped', p_scope, p_scope_id);
    END IF;
    SELECT array_agg(DISTINCT s.agent ORDER BY s.agent), array_agg(s.change_id ORDER BY s.change_id)
      INTO v_agents, v_covered
      FROM basalt_meta._revert_scope(p_scope, p_scope_id) s;
    v_hash := sha256(convert_to(array_to_string(v_lines, E'\n'), 'UTF8'));
    v_batched := cardinality(v_lines) > c_max_lines;
    v_sample := v_lines;
    IF v_batched THEN
        v_sample := ARRAY(SELECT u.l FROM unnest(v_lines) WITH ORDINALITY u(l, n)
                           ORDER BY (u.l::jsonb ->> 'action') = 'RESTORE', u.n
                           LIMIT c_max_lines);
        v_sample_h := sha256(convert_to(array_to_string(v_sample, E'\n'), 'UTF8'));
    END IF;
    v_text := (jsonb_build_object(
        'kind', 'REVERT', 'revertId', v_id, 'database', current_database(), 'scope', p_scope, 'scopeId', p_scope_id,
        'agents', to_jsonb(v_agents::text[]), 'intent', p_intent, 'rows', v_rows,
        'skipped', cardinality(v_lines) - v_rows, 'rowsHash', encode(v_hash, 'hex'),
        'expiresAt', to_char(v_expires AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'requestedBy', session_user)
        || CASE WHEN v_batched THEN jsonb_build_object('batched', true, 'sampleHash', encode(v_sample_h, 'hex'))
                ELSE '{}'::jsonb END)::text;
    INSERT INTO basalt_meta.reverts (revert_id, scope, scope_id, agents, requested_by, intent, lines, rows, skipped,
                                     rows_hash, binding_text, binding, expires_at, batched, sample_hash, covered)
    VALUES (v_id, p_scope, p_scope_id, v_agents, session_user, p_intent, v_sample, v_rows, cardinality(v_lines) - v_rows,
            v_hash, v_text, sha256(convert_to(v_text, 'UTF8')), v_expires, v_batched, v_sample_h, v_covered);
    IF v_batched THEN
        -- Execution order: the writes that landed on trial in the order they
        -- landed, then the lines the trial skipped.
        INSERT INTO basalt_meta.revert_lines (revert_id, line_no, line, chain)
        SELECT v_id, row_number() OVER (ORDER BY it.step NULLS LAST, it.first_seq),
               basalt_meta._revert_line(it, session_user), ch
          FROM unnest(v_items) it JOIN unnest(v_chains) ch ON ch.first_seq = it.first_seq;
    END IF;
    PERFORM basalt_meta._append(session_user, NULL, 'REVERT_PENDING', NULL, NULL, NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', v_id, 'scope', p_scope, 'scopeId', p_scope_id, 'intent', p_intent,
                           'rows', v_rows, 'skipped', cardinality(v_lines) - v_rows,
                           'rowsHash', encode(v_hash, 'hex'), 'expiresAt', v_expires)
        || CASE WHEN v_batched THEN jsonb_build_object('batched', true) ELSE '{}'::jsonb END);
    revert_id := v_id;
    binding_text := v_text;
    expires_at := v_expires;
    lines := v_sample;
    RETURN NEXT;
END $$;
