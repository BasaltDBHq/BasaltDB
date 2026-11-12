package guard

// Version 17: a batched plan's sample keeps room for both kinds of line
// (decision RSS-1, amending N12-4). Up to version 16 the sample was the first
// 1000 lines with SKIP lines first, so a plan with 1000 or more SKIP lines
// showed the person no RESTORE line at all. prepare_revert is the same as
// version 9's except for the sample, which _revert_sample now builds as
// revert.Sample does in Go.
const v17RevertSample = `
-- The lines a batched plan's link carries: up to half of p_max SKIP lines
-- and up to half RESTORE lines; when one kind has fewer, the other fills
-- the rest, at most p_max in all. SKIP lines first, each kind in signed
-- order (decision RSS-1). Must match revert.Sample and revert.SampleCounts.
CREATE OR REPLACE FUNCTION basalt_meta._revert_sample(p_lines text[], p_max int) RETURNS text[]
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
    WITH l AS (
        SELECT u.l, u.n, (u.l::jsonb ->> 'action') = 'RESTORE' AS restore,
               row_number() OVER (PARTITION BY (u.l::jsonb ->> 'action') = 'RESTORE' ORDER BY u.n) AS k
          FROM unnest(p_lines) WITH ORDINALITY u(l, n)
    ), c AS (
        SELECT count(*) FILTER (WHERE NOT l.restore)::int AS skips,
               count(*) FILTER (WHERE l.restore)::int AS restores
          FROM l
    ), t AS (
        SELECT least(c.skips, greatest(p_max / 2, p_max - c.restores)) AS skips, c.restores FROM c
    )
    SELECT coalesce(array_agg(l.l ORDER BY l.restore, l.n), '{}')
      FROM l, t
     WHERE (NOT l.restore AND l.k <= t.skips)
        OR (l.restore AND l.k <= least(t.restores, p_max - t.skips))
$$;

-- Version 9's prepare_revert with the sample from _revert_sample. rowsHash
-- still covers every line; sampleHash covers the sample.
CREATE OR REPLACE FUNCTION basalt_meta.prepare_revert(p_scope text, p_scope_id uuid, p_intent text)
RETURNS TABLE (revert_id uuid, binding_text text, expires_at timestamptz, lines text[])
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
#variable_conflict use_column
DECLARE
    c_ttl       constant interval := interval '1 hour';
    c_max_lines constant int := 1000; -- one-call revert and lines in a link (M3-9, N12-4, RSS-1)
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
        v_sample := basalt_meta._revert_sample(v_lines, c_max_lines);
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
`
