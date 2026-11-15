-- Signing and applying batched reverts: apply_revert, apply_revert_batch
-- and their checks.

-- The skipped lines of a plan as the preparing role saw them, for ledger
-- details: table, key or row hash, reason; no values.
CREATE FUNCTION basalt_meta._revert_skips(p_revert uuid, p_lines int[]) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
               'line', l.line_no, 'table', l.line::jsonb -> 'table', 'key', l.line::jsonb -> 'key',
               'rowHash', l.line::jsonb -> 'rowHash', 'conflict', l.conflict, 'sqlState', l.sql_state))
             ORDER BY l.line_no), '[]'::jsonb)
      FROM basalt_meta.revert_lines l
     WHERE l.revert_id = p_revert AND l.outcome = 'SKIPPED' AND (p_lines IS NULL OR l.line_no = ANY (p_lines))
$$;

-- A batched plan's totals: lines restored, skipped and pending.
CREATE FUNCTION basalt_meta._revert_progress(p_revert uuid, OUT restored int, OUT skipped int, OUT pending int)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT count(l.line_no) FILTER (WHERE l.outcome = 'RESTORED')::int,
           count(l.line_no) FILTER (WHERE l.outcome = 'SKIPPED')::int,
           count(l.line_no) FILTER (WHERE l.outcome = 'PENDING')::int
      FROM basalt_meta.revert_lines l WHERE l.revert_id = p_revert
$$;

-- The person's signature over a batched plan (decision N12-6): open the
-- revert's change record, mark the SKIP lines skipped, start the 24-hour
-- window (N12-2), and record REVERT_SIGNED. No row of the person's tables
-- is written here.
CREATE FUNCTION basalt_meta._revert_sign(r basalt_meta.reverts, p_credential_id bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    c_window   constant interval := interval '24 hours';
    v_change   uuid := basalt_meta._uuidv7();
    v_apply_by timestamptz := now() + c_window;
    v_progress record;
BEGIN
    INSERT INTO basalt_meta.changes (change_id, tx, stmt_ts, agent, intent, op, rows, mode, status,
                                     actor_kind, revert_id, credential_id)
    VALUES (v_change, pg_current_xact_id(), statement_timestamp(), session_user, r.intent, 'REVERT', 0, 'APPLY',
            'APPLIED', 'PERSON', r.revert_id, p_credential_id);
    UPDATE basalt_meta.revert_lines l
       SET outcome = 'SKIPPED', batch = 0, conflict = l.line::jsonb ->> 'conflict', sql_state = l.line::jsonb ->> 'sqlState'
     WHERE l.revert_id = r.revert_id AND l.line::jsonb ->> 'action' = 'SKIP';
    UPDATE basalt_meta.reverts x
       SET signed_at = now(), apply_by = v_apply_by, credential_id = p_credential_id, change_id = v_change
     WHERE x.revert_id = r.revert_id;
    SELECT * INTO v_progress FROM basalt_meta._revert_progress(r.revert_id);
    PERFORM basalt_meta._append(session_user, v_change, 'REVERT_SIGNED', NULL, 'REVERT', NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', r.revert_id, 'scope', r.scope, 'scopeId', r.scope_id, 'intent', r.intent,
                           'credentialId', encode(p_credential_id, 'hex'), 'binding', encode(r.binding, 'hex'),
                           'lines', r.rows + r.skipped, 'rows', r.rows,
                           'skipped', basalt_meta._revert_skips(r.revert_id, NULL), 'applyBy', v_apply_by));
    RETURN jsonb_build_object('changeId', v_change, 'rows', 0, 'skipped', v_progress.skipped, 'batched', true,
                              'pending', v_progress.pending,
                              'applyBy', to_char(v_apply_by AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
END $$;

-- Any relay (version 7): verify the person's assertion over a prepared
-- revert and run it in the same call; for a batched plan, record the
-- signature only (_revert_sign).
CREATE OR REPLACE FUNCTION basalt_meta.apply_revert(
    p_revert_id uuid, p_credential_id bytea, p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
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
        PERFORM basalt_meta._revert_invalid('revert already applied');
    END IF;
    IF r.signed_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_invalid('revert already signed; the agent applies it in batches');
    END IF;
    IF r.expires_at <= now() THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'REVERT_EXPIRED',
            DETAIL = format('revert %s expired at %s; prepare it again', r.revert_id, r.expires_at);
    END IF;
    BEGIN
        PERFORM basalt_meta._verify_assertion(r.binding, p_credential_id, p_authenticator_data, p_client_data_json, p_signature);
    EXCEPTION WHEN SQLSTATE 'BS005' THEN
        GET STACKED DIAGNOSTICS v_detail = PG_EXCEPTION_DETAIL;
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
    v_items := basalt_meta._revert_execute(basalt_meta._revert_items(r.scope, r.scope_id, true));
    v_lines := basalt_meta._revert_text(v_items, r.requested_by);
    DELETE FROM basalt_meta.revert_running x WHERE x.tx = pg_current_xact_id();
    IF sha256(convert_to(array_to_string(v_lines, E'\n'), 'UTF8')) <> r.rows_hash THEN
        PERFORM basalt_meta._revert_invalid('rows changed since the preview; nothing was reverted, prepare the revert again');
    END IF;

    SELECT count(x.table_oid)::int INTO v_rows FROM unnest(v_items) x WHERE x.conflict IS NULL;
    UPDATE basalt_meta.changes x SET rows = v_rows WHERE x.change_id = v_change;
    -- A change is REVERTED when none of its rows was skipped; a partly
    -- reverted change stays APPLIED and names the revert (M3-8).
    UPDATE basalt_meta.changes c
       SET reverted_by = coalesce(c.reverted_by, '{}'::uuid[]) || v_change,
           status = CASE WHEN EXISTS (SELECT 1 FROM unnest(v_items) x WHERE x.conflict IS NOT NULL AND c.change_id = ANY (x.change_ids))
                         THEN c.status ELSE 'REVERTED' END
     WHERE c.change_id IN (SELECT s.change_id FROM basalt_meta._revert_scope(r.scope, r.scope_id) s)
       AND (EXISTS (SELECT 1 FROM unnest(v_items) x WHERE x.conflict IS NULL AND c.change_id = ANY (x.change_ids))
            OR NOT EXISTS (SELECT 1 FROM unnest(v_items) x WHERE c.change_id = ANY (x.change_ids)));
    UPDATE basalt_meta.reverts x SET applied_at = now(), credential_id = p_credential_id, change_id = v_change
     WHERE x.revert_id = r.revert_id;

    SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
               'table', l -> 'table', 'key', l -> 'key', 'rowHash', l -> 'rowHash',
               'conflict', l -> 'conflict', 'sqlState', l -> 'sqlState')) ORDER BY n), '[]'::jsonb)
      INTO v_skipped
      FROM unnest(v_lines) WITH ORDINALITY u(t, n) CROSS JOIN LATERAL (SELECT u.t::jsonb AS l) j
     WHERE l ->> 'action' = 'SKIP';
    PERFORM basalt_meta._append(session_user, v_change, 'REVERTED', NULL, 'REVERT', NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', r.revert_id, 'scope', r.scope, 'scopeId', r.scope_id, 'intent', r.intent,
                           'credentialId', encode(p_credential_id, 'hex'), 'binding', encode(r.binding, 'hex'),
                           'rows', v_rows, 'skipped', v_skipped));
    RETURN jsonb_build_object('changeId', v_change, 'rows', v_rows, 'skipped', cardinality(v_lines) - v_rows);
END $$;

-- One line of a signed plan re-checked with its row locked (decision
-- N12-5): the item recomputed from the stored chain, skipped as
-- CHANGED_AFTER when it no longer matches the signed line.
CREATE FUNCTION basalt_meta._revert_recheck(l basalt_meta.revert_lines, p_role name) RETURNS basalt_meta.revert_item
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    it basalt_meta.revert_item := basalt_meta._revert_item(l.chain, true);
BEGIN
    IF it.conflict IS NULL AND basalt_meta._revert_line(it, p_role) IS DISTINCT FROM l.line THEN
        it.conflict := 'CHANGED_AFTER';
    END IF;
    RETURN it;
END $$;

-- The last batch of a plan: the plan is applied, and each covered change
-- is REVERTED when every line naming it was restored (changes with no
-- line count as restored, as in M3-8).
CREATE FUNCTION basalt_meta._revert_finish(r basalt_meta.reverts, p_batches int) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_progress record;
BEGIN
    SELECT * INTO v_progress FROM basalt_meta._revert_progress(r.revert_id);
    UPDATE basalt_meta.reverts x SET applied_at = now() WHERE x.revert_id = r.revert_id;
    WITH per AS (
        SELECT u.cid, bool_and(l.outcome = 'RESTORED') AS all_restored, bool_or(l.outcome = 'RESTORED') AS any_restored
          FROM basalt_meta.revert_lines l CROSS JOIN LATERAL unnest((l.chain).change_ids) u(cid)
         WHERE l.revert_id = r.revert_id
         GROUP BY u.cid
    ), covered AS (
        SELECT c.cid, p.all_restored, p.any_restored FROM unnest(r.covered) c(cid) LEFT JOIN per p ON p.cid = c.cid
    )
    UPDATE basalt_meta.changes c
       SET reverted_by = CASE WHEN r.change_id = ANY (coalesce(c.reverted_by, '{}'::uuid[])) THEN c.reverted_by
                              ELSE coalesce(c.reverted_by, '{}'::uuid[]) || r.change_id END,
           status = CASE WHEN coalesce(v.all_restored, true) THEN 'REVERTED' ELSE c.status END
      FROM covered v
     WHERE c.change_id = v.cid AND (v.any_restored OR v.all_restored IS NULL);
    PERFORM basalt_meta._append(session_user, r.change_id, 'REVERTED', NULL, 'REVERT', NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', r.revert_id, 'scope', r.scope, 'scopeId', r.scope_id, 'intent', r.intent,
                           'rows', v_progress.restored, 'skipped', v_progress.skipped, 'batches', p_batches));
END $$;

-- The role that prepared a signed batched plan: apply up to 200 of its
-- pending lines (decisions N12-3, N12-5, N12-6). Checked against the
-- signed plan before anything is written: only lines of this plan, each
-- at most once, within 24 hours of the signature. Each line is re-checked
-- with its row locked; a row someone changed is skipped (people win).
CREATE FUNCTION basalt_meta.apply_revert_batch(p_revert_id uuid, p_lines int[]) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    c_max_batch constant int := 200;
    r          basalt_meta.reverts;
    v_batch    int;
    v_bad      int;
    v_done     int;
    v_items    basalt_meta.revert_item[];
    v_rows     int;
    v_progress record;
BEGIN
    PERFORM basalt_meta._require_agent();
    SELECT * INTO r FROM basalt_meta.reverts x
     WHERE x.revert_id = p_revert_id AND x.requested_by = session_user FOR UPDATE;
    IF NOT FOUND THEN
        PERFORM basalt_meta._revert_invalid('no such revert');
    END IF;
    IF NOT r.batched THEN
        PERFORM basalt_meta._revert_invalid(format('revert %s is applied in one call by basalt revert, not in batches', r.revert_id));
    END IF;
    IF r.signed_at IS NULL THEN
        PERFORM basalt_meta._revert_invalid('the person has not signed this revert yet (basalt revert)');
    END IF;
    IF r.applied_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_invalid('revert already applied: no line is pending');
    END IF;
    IF r.apply_by <= now() THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'REVERT_EXPIRED',
            DETAIL = format('signed revert %s had to be applied by %s; prepare it again', r.revert_id, r.apply_by);
    END IF;
    IF coalesce(cardinality(p_lines), 0) NOT BETWEEN 1 AND c_max_batch THEN
        PERFORM basalt_meta._revert_invalid(format('a batch has 1 to %s lines', c_max_batch));
    END IF;
    SELECT n INTO v_bad FROM unnest(p_lines) n GROUP BY n HAVING count(n) > 1 ORDER BY n LIMIT 1;
    IF FOUND THEN
        PERFORM basalt_meta._revert_invalid(format('the batch names line %s twice', v_bad));
    END IF;
    SELECT n INTO v_bad FROM unnest(p_lines) n
     WHERE NOT EXISTS (SELECT 1 FROM basalt_meta.revert_lines l WHERE l.revert_id = r.revert_id AND l.line_no = n)
     ORDER BY n LIMIT 1;
    IF FOUND THEN
        PERFORM basalt_meta._revert_invalid(format('line %s is not in the plan', coalesce(v_bad::text, 'NULL')));
    END IF;
    SELECT l.line_no, l.batch INTO v_bad, v_done FROM basalt_meta.revert_lines l
     WHERE l.revert_id = r.revert_id AND l.line_no = ANY (p_lines) AND l.outcome <> 'PENDING'
     ORDER BY l.line_no LIMIT 1;
    IF FOUND THEN
        PERFORM basalt_meta._revert_invalid(format('line %s was already applied in batch %s', v_bad, v_done));
    END IF;

    v_batch := r.batches + 1;
    PERFORM set_config('lock_timeout', '5s', true);
    INSERT INTO basalt_meta.revert_running (tx, agent, change_id) VALUES (pg_current_xact_id(), session_user, r.change_id);
    v_items := basalt_meta._revert_execute(ARRAY(
        SELECT basalt_meta._revert_recheck(l, r.requested_by) FROM basalt_meta.revert_lines l
         WHERE l.revert_id = r.revert_id AND l.line_no = ANY (p_lines) ORDER BY l.line_no));
    DELETE FROM basalt_meta.revert_running x WHERE x.tx = pg_current_xact_id();

    UPDATE basalt_meta.revert_lines l
       SET outcome = CASE WHEN x.conflict IS NULL THEN 'RESTORED' ELSE 'SKIPPED' END,
           conflict = x.conflict, sql_state = x.sql_state, batch = v_batch
      FROM unnest(v_items) x
     WHERE l.revert_id = r.revert_id AND l.line_no = ANY (p_lines) AND (l.chain).first_seq = x.first_seq;
    SELECT count(x.table_oid)::int INTO v_rows FROM unnest(v_items) x WHERE x.conflict IS NULL;
    UPDATE basalt_meta.changes c SET rows = c.rows + v_rows WHERE c.change_id = r.change_id;
    UPDATE basalt_meta.changes c SET reverted_by = coalesce(c.reverted_by, '{}'::uuid[]) || r.change_id
     WHERE c.change_id IN (SELECT DISTINCT u.cid FROM unnest(v_items) x CROSS JOIN LATERAL unnest(x.change_ids) u(cid)
                            WHERE x.conflict IS NULL)
       AND NOT (r.change_id = ANY (coalesce(c.reverted_by, '{}'::uuid[])));
    UPDATE basalt_meta.reverts x SET batches = v_batch WHERE x.revert_id = r.revert_id;
    SELECT * INTO v_progress FROM basalt_meta._revert_progress(r.revert_id);
    PERFORM basalt_meta._append(session_user, r.change_id, 'REVERT_BATCH', NULL, 'REVERT', NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', r.revert_id, 'batch', v_batch,
                           'lines', (SELECT to_jsonb(array_agg(n ORDER BY n)) FROM unnest(p_lines) n),
                           'rows', v_rows, 'skipped', basalt_meta._revert_skips(r.revert_id, p_lines),
                           'pending', v_progress.pending));
    IF v_progress.pending = 0 THEN
        PERFORM basalt_meta._revert_finish(r, v_batch);
    END IF;
    RETURN jsonb_build_object(
        'revertId', r.revert_id, 'batch', v_batch,
        'status', CASE WHEN v_progress.pending = 0 THEN 'APPLIED' ELSE 'APPLYING' END,
        'restored', v_progress.restored, 'skipped', v_progress.skipped, 'pending', v_progress.pending,
        'items', (SELECT jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
                             'line', l.line_no, 'outcome', l.outcome, 'conflict', l.conflict, 'sqlState', l.sql_state))
                           ORDER BY u.n)
                    FROM unnest(p_lines) WITH ORDINALITY u(no, n)
                    JOIN basalt_meta.revert_lines l ON l.revert_id = r.revert_id AND l.line_no = u.no));
END $$;
