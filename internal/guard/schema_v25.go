package guard

// Version 25: approval and revert deadlines are read from the wall clock
// (CONTRACT.md, basalt_meta "Version 25"). Up to version 24 every expiry
// check compared with now(), which Postgres fixes when the transaction
// starts, so an agent that opened a transaction before an approval or a
// revert expired could still submit, apply and commit it afterwards, as
// long as it kept the transaction open. Each check now reads
// clock_timestamp(), after the row lock where there is one, as
// record_setup does since version 18.
//
// The functions are replaced with their latest version otherwise
// unchanged, attributes restated (CREATE OR REPLACE resets what it does
// not name; owner and grants are kept), except:
//
//   - submit_approval records the same clock reading as approved_at and
//     returns it;
//   - _check_approval is no longer STABLE: it reads the clock.
//
// Idempotent.
const v25Approvals = `
-- Any relay (version 4): the person's passkey assertion over the
-- approval's binding. The relay is untrusted; only a valid signature
-- counts.
CREATE OR REPLACE FUNCTION basalt_meta.submit_approval(
    p_approval_id uuid, p_credential_id bytea, p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea
) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    a    basalt_meta.approvals;
    v_at timestamptz;
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
    -- The time now, read after the lock: not the transaction's start.
    v_at := clock_timestamp();
    IF a.expires_at <= v_at THEN
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
CREATE OR REPLACE FUNCTION basalt_meta._check_approval(p_id uuid, p_run uuid) RETURNS basalt_meta.approvals
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
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
    IF a.expires_at <= clock_timestamp() THEN
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
CREATE OR REPLACE FUNCTION basalt_meta._commit_approval(c basalt_meta.changes) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
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
    IF a.expires_at <= clock_timestamp() THEN
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
`

// v25Reverts is the revert half of version 25: _revert_lock_pending,
// apply_revert and apply_revert_batch check their deadlines with
// clock_timestamp().
const v25Reverts = `
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
`
