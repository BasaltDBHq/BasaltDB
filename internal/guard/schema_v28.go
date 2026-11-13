package guard

// Version 28: one clock for what the person did, and search_path on every
// routine (CONTRACT.md, basalt_meta "Version 28").
//
//   - The times recorded for the person's acts read the wall clock
//     (clock_timestamp()), the clock version 25 checks deadlines against:
//     applied_at (apply_revert, and _revert_finish for the last batch),
//     signed_at with the apply_by window that starts at it (_revert_sign),
//     and rejected_at (reject_revert, read after the revert is locked).
//     approved_at already does since version 25. Up to version 27 these
//     recorded the transaction's start (now()), which can be earlier than
//     the deadline check that let them through. The functions are replaced
//     with their latest version otherwise unchanged, attributes restated
//     (CREATE OR REPLACE resets what it does not name; owner and grants
//     are kept).
//   - v28SearchPath sets search_path = pg_catalog, pg_temp on every
//     function and procedure in basalt_meta (ALTER ROUTINE). Version 24's
//     loop took functions only (prokind 'f'); TestEveryGuardFunctionPutsPgTempLast
//     checks every routine.
//
// Idempotent.
const v28RecordedTimes = `
-- Any relay (version 25): verify the person's assertion over a prepared
-- revert and run it in the same call; for a batched plan, record the
-- signature only. applied_at reads the wall clock.
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
    UPDATE basalt_meta.reverts x SET applied_at = clock_timestamp(), credential_id = p_credential_id, change_id = v_change
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

-- The person's signature over a batched plan (version 9): signed_at and the
-- 24-hour window from one reading of the wall clock.
CREATE OR REPLACE FUNCTION basalt_meta._revert_sign(r basalt_meta.reverts, p_credential_id bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_window   constant interval := interval '24 hours';
    v_change   uuid := basalt_meta._uuidv7();
    v_signed   timestamptz := clock_timestamp();
    v_apply_by timestamptz := v_signed + c_window;
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
       SET signed_at = v_signed, apply_by = v_apply_by, credential_id = p_credential_id, change_id = v_change
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

-- The last batch of a plan (version 20): applied_at reads the wall clock.
CREATE OR REPLACE FUNCTION basalt_meta._revert_finish(r basalt_meta.reverts, p_batches int) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_progress record;
BEGIN
    SELECT * INTO v_progress FROM basalt_meta._revert_progress(r.revert_id);
    UPDATE basalt_meta.reverts x SET applied_at = clock_timestamp() WHERE x.revert_id = r.revert_id;
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
           status = CASE WHEN coalesce(v.all_restored, true) AND basalt_meta._revert_whole(r.selection, c.change_id)
                         THEN 'REVERTED' ELSE c.status END
      FROM covered v
     WHERE c.change_id = v.cid AND (v.any_restored OR v.all_restored IS NULL);
    PERFORM basalt_meta._append(session_user, r.change_id, 'REVERTED', NULL, 'REVERT', NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', r.revert_id, 'scope', r.scope, 'scopeId', r.scope_id, 'intent', r.intent,
                           'rows', v_progress.restored, 'skipped', v_progress.skipped, 'batches', p_batches));
END $$;

-- Agent, for the engine's reject route (version 23): rejected_at reads the
-- wall clock after the revert is locked.
CREATE OR REPLACE FUNCTION basalt_meta.reject_revert(p_revert_id uuid, p_note text, p_token bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    r      basalt_meta.reverts;
    v_note text := nullif(p_note, '');
    v_via  text := 'LINK_OR_AGENT';
    v_at   timestamptz;
BEGIN
    PERFORM basalt_meta._require_agent();
    IF char_length(v_note) > 500 THEN
        RAISE EXCEPTION USING ERRCODE = 'BS008', MESSAGE = 'LEDGER_INPUT_INVALID',
            DETAIL = 'a reject note is at most 500 characters';
    END IF;
    r := basalt_meta._revert_lock_pending(p_revert_id);
    v_at := clock_timestamp();
    CASE
    WHEN r.ceiling IS NULL AND p_token IS NULL THEN
        v_via := 'LINK_OR_AGENT';
    WHEN r.ceiling IS NOT NULL AND p_token IS NOT NULL AND sha256(p_token) = r.scope_token_hash THEN
        v_via := 'SCOPE_TOKEN';
    ELSE
        PERFORM basalt_meta._widen_refused();
    END CASE;
    UPDATE basalt_meta.reverts x SET rejected_at = v_at, reject_note = v_note WHERE x.revert_id = r.revert_id;
    PERFORM basalt_meta._append(session_user, NULL, 'REVERT_REJECTED', NULL, NULL, NULL, NULL, NULL, NULL,
        pg_catalog.jsonb_strip_nulls(jsonb_build_object('revertId', r.revert_id, 'note', v_note, 'via', v_via)));
    RETURN jsonb_build_object('revertId', r.revert_id, 'status', 'REJECTED', 'rejectedAt', v_at);
END $$;
`

// v28SearchPath is version 24's loop over every routine kind that takes a
// SET clause: functions and procedures. Aggregates and window functions
// cannot have one; basalt_meta has none.
const v28SearchPath = `
DO $$
DECLARE
    f regprocedure;
BEGIN
    FOR f IN SELECT p.oid::regprocedure FROM pg_catalog.pg_proc p
              WHERE p.pronamespace = 'basalt_meta'::pg_catalog.regnamespace AND p.prokind IN ('f', 'p')
                AND p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp']
              ORDER BY 1 LOOP
        EXECUTE pg_catalog.format('ALTER ROUTINE %s SET search_path = pg_catalog, pg_temp', f);
    END LOOP;
END $$;
`
