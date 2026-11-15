-- v25Reverts is the revert half of version 25: _revert_lock_pending,
-- apply_revert and apply_revert_batch check their deadlines with
-- clock_timestamp().

-- The caller's own revert p_revert_id, locked, while its scope may still
-- change (version 21): not applied, rejected, signed or expired. Another
-- role's revert reads like one that does not exist.
CREATE OR REPLACE FUNCTION basalt_meta._revert_lock_pending(p_revert_id uuid) RETURNS basalt_meta.reverts
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
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
    IF r.expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'REVERT_EXPIRED',
            DETAIL = format('revert %s expired at %s; prepare it again', r.revert_id, r.expires_at);
    END IF;
    RETURN r;
END $$;

-- Any relay (version 20): verify the person's assertion over a prepared
-- revert and run it in the same call; for a batched plan, record the
-- signature only.
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
        PERFORM basalt_meta._revert_invalid('revert already applied');
    END IF;
    IF r.rejected_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_invalid('the person rejected this revert; nothing was reverted');
    END IF;
    IF r.signed_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_invalid('revert already signed; the agent applies it in batches');
    END IF;
    IF r.expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'REVERT_EXPIRED',
            DETAIL = format('revert %s expired at %s; prepare it again', r.revert_id, r.expires_at);
    END IF;
    IF (r.binding_text::jsonb -> 'select') IS DISTINCT FROM r.selection THEN
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
        PERFORM basalt_meta._revert_invalid('rows changed since the preview; nothing was reverted, prepare the revert again');
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
    UPDATE basalt_meta.reverts x SET applied_at = now(), credential_id = p_credential_id, change_id = v_change
     WHERE x.revert_id = r.revert_id;

    SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
               'table', l -> 'table', 'key', l -> 'key', 'rowHash', l -> 'rowHash',
               'conflict', l -> 'conflict', 'sqlState', l -> 'sqlState')) ORDER BY n), '[]'::jsonb)
      INTO v_skipped
      FROM unnest(v_lines) WITH ORDINALITY u(t, n) CROSS JOIN LATERAL (SELECT u.t::jsonb AS l) j
     WHERE l ->> 'action' = 'SKIP';
    PERFORM basalt_meta._append(session_user, v_change, 'REVERTED', NULL, 'REVERT', NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', r.revert_id, 'scope', r.scope, 'scopeId', r.scope_id, 'select', r.selection,
                           'intent', r.intent, 'credentialId', encode(p_credential_id, 'hex'),
                           'binding', encode(r.binding, 'hex'), 'rows', v_rows, 'skipped', v_skipped));
    RETURN jsonb_build_object('changeId', v_change, 'rows', v_rows, 'skipped', cardinality(v_lines) - v_rows);
END $$;

-- The role that prepared a signed batched plan (version 9): apply up to
-- 200 of its pending lines, within 24 hours of the signature.
CREATE OR REPLACE FUNCTION basalt_meta.apply_revert_batch(p_revert_id uuid, p_lines int[]) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
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
    IF r.apply_by <= clock_timestamp() THEN
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
