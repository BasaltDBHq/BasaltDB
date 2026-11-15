-- preview_revert and prepare_revert over a scope descriptor.

-- Agent (MCP preview_revert, basalt revert --dry-run): what reverting the
-- agent's own proposal p_select would do, from a trial run that always
-- rolls back. Needs a read-write transaction; it leaves nothing behind.
CREATE OR REPLACE FUNCTION basalt_meta.preview_revert(p_select jsonb) RETURNS SETOF text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_sel jsonb;
BEGIN
    PERFORM basalt_meta._require_agent();
    v_sel := basalt_meta._revert_own_select(p_select);
    RETURN QUERY SELECT u.line
      FROM unnest(basalt_meta._revert_trial(basalt_meta._revert_items(v_sel, false), session_user))
           WITH ORDINALITY u(line, n)
     ORDER BY u.n;
END $$;

-- Agent, as the CLI's relay and for request_revert: store the agent's own
-- proposal p_select for the person to sign (version 17 with the scope
-- descriptor). selection = proposed = the normalized descriptor, a fresh
-- rescope nonce, and the binding built from them. A TASK the caller ran in
-- with no line of its own is stored as an empty proposal the person may
-- widen on the page (it cannot be signed as it is); every other scope with
-- nothing to restore is NOTHING_TO_REVERT.
CREATE OR REPLACE FUNCTION basalt_meta.prepare_revert(p_select jsonb, p_intent text)
RETURNS TABLE (revert_id uuid, binding_text text, expires_at timestamptz, lines text[])
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
#variable_conflict use_column
DECLARE
    c_ttl       constant interval := interval '1 hour';
    c_max_lines constant int := 1000; -- one-call revert and lines in a link (M3-9, N12-4, RSS-1)
    v_id        uuid := basalt_meta._uuidv7();
    v_expires   timestamptz := now() + c_ttl;
    v_sel       jsonb;
    v_chains    basalt_meta.revert_chain[];
    v_items     basalt_meta.revert_item[];
    v_lines     text[];
    v_sample    text[];
    v_rows      int;
    v_covered   uuid[];
    v_hash      bytea;
    v_sample_h  bytea;
    v_batched   boolean;
    v_text      text;
BEGIN
    PERFORM basalt_meta._require_agent();
    PERFORM basalt_meta._check_text('intent', p_intent, 2000, true);
    v_sel := basalt_meta._revert_own_select(p_select);
    v_chains := basalt_meta._revert_chain_list(v_sel, v_sel ->> 'scope' = 'TASK');
    v_items := basalt_meta._revert_trial_items(ARRAY(SELECT basalt_meta._revert_item(x, false) FROM unnest(v_chains) x));
    v_lines := basalt_meta._revert_text(v_items, session_user);
    SELECT count(x.table_oid)::int INTO v_rows FROM unnest(v_items) x WHERE x.conflict IS NULL;
    IF v_rows = 0 AND cardinality(v_lines) > 0 THEN
        RAISE EXCEPTION USING ERRCODE = 'BS009', MESSAGE = 'NOTHING_TO_REVERT',
            DETAIL = format('every row of %s %s would be skipped', v_sel ->> 'scope', v_sel ->> 'scopeId');
    END IF;
    SELECT array_agg(s ORDER BY s) INTO v_covered FROM basalt_meta._revert_covered(v_sel) s;
    v_hash := sha256(convert_to(array_to_string(v_lines, E'\n'), 'UTF8'));
    v_batched := cardinality(v_lines) > c_max_lines;
    v_sample := v_lines;
    IF v_batched THEN
        v_sample := basalt_meta._revert_sample(v_lines, c_max_lines);
        v_sample_h := sha256(convert_to(array_to_string(v_sample, E'\n'), 'UTF8'));
    END IF;
    v_text := basalt_meta._revert_binding(v_id, v_sel, v_sel, session_user, p_intent, v_rows,
                                          cardinality(v_lines) - v_rows, v_hash, v_expires, v_sample_h,
                                          basalt_meta._revert_agent_rows(v_items));
    INSERT INTO basalt_meta.reverts (revert_id, selection, proposed, rescope_nonce, requested_by, intent, lines, rows,
                                     skipped, rows_hash, binding_text, binding, expires_at, batched, sample_hash, covered)
    VALUES (v_id, v_sel, v_sel, basalt_meta._revert_nonce(), session_user, p_intent, v_sample, v_rows,
            cardinality(v_lines) - v_rows, v_hash, v_text, sha256(convert_to(v_text, 'UTF8')), v_expires, v_batched,
            v_sample_h, v_covered);
    IF v_batched THEN
        -- Execution order: the writes that landed on trial in the order they
        -- landed, then the lines the trial skipped.
        INSERT INTO basalt_meta.revert_lines (revert_id, line_no, line, chain)
        SELECT v_id, row_number() OVER (ORDER BY it.step NULLS LAST, it.first_seq),
               basalt_meta._revert_line(it, session_user), ch
          FROM unnest(v_items) it JOIN unnest(v_chains) ch ON ch.first_seq = it.first_seq;
    END IF;
    PERFORM basalt_meta._append(session_user, NULL, 'REVERT_PENDING', NULL, NULL, NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', v_id, 'scope', v_sel ->> 'scope', 'scopeId', v_sel ->> 'scopeId',
                           'select', v_sel, 'intent', p_intent, 'rows', v_rows,
                           'skipped', cardinality(v_lines) - v_rows,
                           'rowsHash', encode(v_hash, 'hex'), 'expiresAt', v_expires)
        || CASE WHEN v_batched THEN jsonb_build_object('batched', true) ELSE '{}'::jsonb END);
    revert_id := v_id;
    binding_text := v_text;
    expires_at := v_expires;
    lines := v_sample;
    RETURN NEXT;
END $$;
