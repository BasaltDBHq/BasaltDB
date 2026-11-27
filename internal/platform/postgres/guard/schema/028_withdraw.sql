-- Version 15: withdraw. The agent that asked for a held write, a revert or
-- a plugin approval can withdraw its own request while it still waits for
-- the person: the row records when (withdrawn_at) and the reason the agent
-- gave (withdraw_reason, 1 to 500 characters), and from then on no passkey
-- signature is taken for it. A withdrawn request is never signed, in any
-- order: the functions that take a signature refuse it with the code
-- WITHDRAWN, and a check on each table refuses a row that is both withdrawn
-- and signed. Idempotent.

ALTER TABLE basalt_meta.approvals
    ADD COLUMN IF NOT EXISTS withdrawn_at timestamptz,
    ADD COLUMN IF NOT EXISTS withdraw_reason text;
ALTER TABLE basalt_meta.approvals DROP CONSTRAINT IF EXISTS approvals_withdrawn;
ALTER TABLE basalt_meta.approvals ADD CONSTRAINT approvals_withdrawn
    CHECK ((withdrawn_at IS NULL) = (withdraw_reason IS NULL)
           AND pg_catalog.char_length(withdraw_reason) BETWEEN 1 AND 500
           AND (withdrawn_at IS NULL OR (approved_at IS NULL AND used_by_change IS NULL)));

ALTER TABLE basalt_meta.reverts
    ADD COLUMN IF NOT EXISTS withdrawn_at timestamptz,
    ADD COLUMN IF NOT EXISTS withdraw_reason text;
ALTER TABLE basalt_meta.reverts DROP CONSTRAINT IF EXISTS reverts_withdrawn;
ALTER TABLE basalt_meta.reverts ADD CONSTRAINT reverts_withdrawn
    CHECK ((withdrawn_at IS NULL) = (withdraw_reason IS NULL)
           AND pg_catalog.char_length(withdraw_reason) BETWEEN 1 AND 500
           AND (withdrawn_at IS NULL OR (signed_at IS NULL AND applied_at IS NULL AND rejected_at IS NULL)));

ALTER TABLE basalt_meta.plugin_approvals
    ADD COLUMN IF NOT EXISTS withdrawn_at timestamptz,
    ADD COLUMN IF NOT EXISTS withdraw_reason text;
ALTER TABLE basalt_meta.plugin_approvals DROP CONSTRAINT IF EXISTS plugin_approvals_status_check;
ALTER TABLE basalt_meta.plugin_approvals DROP CONSTRAINT IF EXISTS plugin_approvals_status;
ALTER TABLE basalt_meta.plugin_approvals ADD CONSTRAINT plugin_approvals_status
    CHECK (status IN ('PENDING', 'APPROVED', 'CANCELLED', 'WITHDRAWN'));
ALTER TABLE basalt_meta.plugin_approvals DROP CONSTRAINT IF EXISTS plugin_approvals_withdrawn;
ALTER TABLE basalt_meta.plugin_approvals ADD CONSTRAINT plugin_approvals_withdrawn
    CHECK ((status = 'WITHDRAWN') = (withdrawn_at IS NOT NULL)
           AND (withdrawn_at IS NULL) = (withdraw_reason IS NULL)
           AND pg_catalog.char_length(withdraw_reason) BETWEEN 1 AND 500);

-- A held write's change record reads APPROVAL_WITHDRAWN once withdrawn.
ALTER TABLE basalt_meta.changes DROP CONSTRAINT IF EXISTS changes_status;
ALTER TABLE basalt_meta.changes ADD CONSTRAINT changes_status
    CHECK (status IN ('APPLIED', 'PREVIEW', 'REFUSED', 'APPROVAL_PENDING', 'APPROVAL_EXPIRED', 'APPROVAL_WITHDRAWN', 'REVERTED'));

-- The withdraw reason as the guard takes it: 1 to 500 characters, as the
-- agent heard it from the person. BS008 LEDGER_INPUT_INVALID otherwise.
CREATE OR REPLACE FUNCTION basalt_meta._check_withdraw_reason(p_reason text) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF p_reason IS NULL OR pg_catalog.char_length(p_reason) NOT BETWEEN 1 AND 500 THEN
        RAISE EXCEPTION USING ERRCODE = 'BS008', MESSAGE = 'LEDGER_INPUT_INVALID',
            DETAIL = 'a withdraw reason is 1 to 500 characters';
    END IF;
END $$;

-- The sentence a refused signature of a withdrawn request carries as its
-- hint.
CREATE OR REPLACE FUNCTION basalt_meta._withdrawn_hint(p_reason text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT pg_catalog.format('the agent withdrew this request: %s; nothing changed', p_reason)
$$;

-- Agent: withdraw one of the calling role's own held writes that still
-- waits for the person (not signed, not used, not expired, not withdrawn).
-- Locks the row first. Another role's approval, or none, is APPROVAL_INVALID
-- NO_SUCH_APPROVAL. Returns when it was withdrawn, or NULL when the
-- approval is no longer waiting, which is left as it is. The held write's
-- change record becomes APPROVAL_WITHDRAWN and APPROVAL_WITHDRAWN is
-- appended with the approval id and the reason.
CREATE OR REPLACE FUNCTION basalt_meta.withdraw_approval(p_approval_id uuid, p_reason text) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    a    basalt_meta.approvals;
    v_at timestamptz;
BEGIN
    PERFORM basalt_meta._require_agent();
    PERFORM basalt_meta._check_withdraw_reason(p_reason);
    SELECT * INTO a FROM basalt_meta.approvals x
     WHERE x.approval_id = p_approval_id AND x.agent = session_user FOR UPDATE;
    IF NOT FOUND THEN
        PERFORM basalt_meta._approval_invalid('no such approval');
    END IF;
    v_at := pg_catalog.clock_timestamp();
    IF a.used_by_change IS NOT NULL OR a.approved_at IS NOT NULL OR a.withdrawn_at IS NOT NULL OR a.expires_at <= v_at THEN
        RETURN NULL;
    END IF;
    UPDATE basalt_meta.approvals x SET withdrawn_at = v_at, withdraw_reason = p_reason
     WHERE x.approval_id = a.approval_id;
    UPDATE basalt_meta.changes c SET status = 'APPROVAL_WITHDRAWN'
     WHERE c.change_id = a.held_change AND c.status = 'APPROVAL_PENDING';
    PERFORM basalt_meta._append(a.agent, a.held_change, 'APPROVAL_WITHDRAWN', NULL, NULL, NULL, NULL, NULL, NULL,
        pg_catalog.jsonb_build_object('approvalId', a.approval_id, 'reason', p_reason));
    RETURN v_at;
END $$;

-- Agent: withdraw a revert the calling role prepared that still waits for
-- the person (not signed, applied, rejected, expired or withdrawn). Locks
-- the row first. Another role's revert, or none, is REVERT_INVALID
-- NO_SUCH_REVERT. Returns when it was withdrawn, or NULL when the revert is
-- no longer waiting, which is left as it is. Appends REVERT_WITHDRAWN with
-- the revert id and the reason.
CREATE OR REPLACE FUNCTION basalt_meta.withdraw_revert(p_revert_id uuid, p_reason text) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    r    basalt_meta.reverts;
    v_at timestamptz;
BEGIN
    PERFORM basalt_meta._require_agent();
    PERFORM basalt_meta._check_withdraw_reason(p_reason);
    SELECT * INTO r FROM basalt_meta.reverts x
     WHERE x.revert_id = p_revert_id AND x.requested_by = session_user FOR UPDATE;
    IF NOT FOUND THEN
        PERFORM basalt_meta._revert_invalid('no such revert');
    END IF;
    v_at := pg_catalog.clock_timestamp();
    IF r.applied_at IS NOT NULL OR r.signed_at IS NOT NULL OR r.rejected_at IS NOT NULL
       OR r.withdrawn_at IS NOT NULL OR r.expires_at <= v_at THEN
        RETURN NULL;
    END IF;
    UPDATE basalt_meta.reverts x SET withdrawn_at = v_at, withdraw_reason = p_reason
     WHERE x.revert_id = r.revert_id;
    PERFORM basalt_meta._append(session_user, NULL, 'REVERT_WITHDRAWN', NULL, NULL, NULL, NULL, NULL, NULL,
        pg_catalog.jsonb_build_object('revertId', r.revert_id, 'reason', p_reason));
    RETURN v_at;
END $$;

-- Agent: withdraw a plugin approval the calling role opened that still
-- waits for the person (PENDING and not expired). Takes the table lock
-- submit_plugin_approval takes, then the row's. An approval the role did
-- not open, or none, is APPROVAL_INVALID NOT_FOUND, as on the page. Returns
-- when it was withdrawn, or NULL when the approval is no longer waiting,
-- which is left as it is. Appends PLUGIN_APPROVAL_WITHDRAWN, which names no
-- agent, to the opener's ledger.
CREATE OR REPLACE FUNCTION basalt_meta.withdraw_plugin_approval(p_approval_id uuid, p_reason text) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    a    basalt_meta.plugin_approvals;
    v_at timestamptz;
BEGIN
    PERFORM basalt_meta._require_agent();
    PERFORM basalt_meta._check_withdraw_reason(p_reason);
    LOCK TABLE basalt_meta.plugin_approvals IN ROW EXCLUSIVE MODE;
    SELECT * INTO a FROM basalt_meta.plugin_approvals x
     WHERE x.approval_id = p_approval_id AND x.opened_by = session_user FOR UPDATE;
    IF NOT FOUND THEN
        PERFORM basalt_meta._approval_invalid('NOT_FOUND');
    END IF;
    v_at := pg_catalog.clock_timestamp();
    IF a.status <> 'PENDING' OR a.expires_at <= v_at THEN
        RETURN NULL;
    END IF;
    UPDATE basalt_meta.plugin_approvals x SET status = 'WITHDRAWN', withdrawn_at = v_at, withdraw_reason = p_reason
     WHERE x.approval_id = a.approval_id;
    PERFORM basalt_meta._append(session_user, NULL, 'PLUGIN_APPROVAL_WITHDRAWN', NULL, NULL, NULL, NULL, NULL, NULL,
        pg_catalog.jsonb_build_object('approvalId', a.approval_id, 'name', a.name, 'instance', a.instance, 'reason', p_reason));
    RETURN v_at;
END $$;

-- Version 1's submit_approval, refusing a withdrawn approval: APPROVAL_INVALID
-- with detail WITHDRAWN and the reason in the hint, after the lock and
-- before the passkey check.
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
    IF a.withdrawn_at IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'APPROVAL_INVALID', DETAIL = 'WITHDRAWN',
            HINT = basalt_meta._withdrawn_hint(a.withdraw_reason);
    END IF;
    IF a.used_by_change IS NOT NULL THEN
        PERFORM basalt_meta._approval_invalid('approval already used');
    END IF;
    IF a.approved_at IS NOT NULL THEN
        PERFORM basalt_meta._approval_invalid('approval already signed');
    END IF;
    -- The time now, read after the lock: not the transaction's start.
    v_at := pg_catalog.clock_timestamp();
    IF a.expires_at <= v_at THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'APPROVAL_EXPIRED',
            DETAIL = pg_catalog.format('approval %s expired at %s', a.approval_id, a.expires_at);
    END IF;
    PERFORM basalt_meta._verify_assertion(a.binding, p_credential_id, p_authenticator_data, p_client_data_json, p_signature);
    UPDATE basalt_meta.approvals x SET approved_at = v_at, credential_id = p_credential_id
     WHERE x.approval_id = a.approval_id;
    PERFORM basalt_meta._append(a.agent, a.held_change, 'APPROVED', NULL, NULL, NULL, NULL, NULL, NULL,
        pg_catalog.jsonb_build_object('approvalId', a.approval_id, 'credentialId', pg_catalog.encode(p_credential_id, 'hex'),
                                      'relayedBy', session_user));
    RETURN v_at;
END $$;

-- Version 4's submit_plugin_approval, refusing a withdrawn approval:
-- APPROVAL_INVALID with detail WITHDRAWN and the reason in the hint.
CREATE OR REPLACE FUNCTION basalt_meta.submit_plugin_approval(
    p_approval_id uuid, p_credential_id bytea, p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea
) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    a        basalt_meta.plugin_approvals;
    v_at     timestamptz;
    v_detail jsonb;
    v_agent  text;
BEGIN
    PERFORM basalt_meta._require_agent();
    LOCK TABLE basalt_meta.plugin_approvals IN ROW EXCLUSIVE MODE;
    SELECT * INTO a FROM basalt_meta.plugin_approvals x WHERE x.approval_id = p_approval_id FOR UPDATE;
    IF NOT FOUND THEN
        PERFORM basalt_meta._approval_invalid('NOT_FOUND');
    END IF;
    IF a.status = 'WITHDRAWN' THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'APPROVAL_INVALID', DETAIL = 'WITHDRAWN',
            HINT = basalt_meta._withdrawn_hint(a.withdraw_reason);
    END IF;
    IF a.status = 'CANCELLED' THEN
        PERFORM basalt_meta._approval_invalid('CANCELLED');
    END IF;
    IF a.status = 'APPROVED' THEN
        PERFORM basalt_meta._approval_invalid('ALREADY_APPROVED');
    END IF;
    -- The time now, read after the lock: not the transaction's start.
    v_at := pg_catalog.clock_timestamp();
    IF a.expires_at <= v_at THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'APPROVAL_EXPIRED',
            DETAIL = pg_catalog.format('plugin approval %s expired at %s', a.approval_id, a.expires_at);
    END IF;
    PERFORM basalt_meta._verify_assertion(a.binding, p_credential_id, p_authenticator_data, p_client_data_json, p_signature);
    UPDATE basalt_meta.plugin_approvals x SET status = 'APPROVED', approved_at = v_at, credential_id = p_credential_id
     WHERE x.approval_id = a.approval_id;
    v_detail := (a.detail - 'expiresAt') || pg_catalog.jsonb_build_object(
        'credentialId', basalt_meta._b64url(p_credential_id), 'bindingSha256', pg_catalog.encode(a.binding, 'hex'));
    FOREACH v_agent IN ARRAY a.agents LOOP
        PERFORM basalt_meta._append(v_agent::name, NULL, 'PLUGIN_APPROVED', NULL, NULL, NULL, NULL, NULL, NULL, v_detail);
    END LOOP;
    RETURN v_at;
END $$;

-- Version 1's _revert_lock_pending (rescope_revert, reset_revert and
-- reject_revert), refusing a withdrawn revert: REVERT_INVALID with detail
-- WITHDRAWN and the reason in the hint.
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
    IF r.withdrawn_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_refused('WITHDRAWN', basalt_meta._withdrawn_hint(r.withdraw_reason));
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
    IF r.expires_at <= pg_catalog.clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'REVERT_EXPIRED',
            DETAIL = pg_catalog.format('revert %s expired at %s; prepare it again', r.revert_id, r.expires_at);
    END IF;
    RETURN r;
END $$;

-- Version 11's apply_revert, refusing a withdrawn revert: REVERT_INVALID
-- with detail WITHDRAWN and the reason in the hint, after the lock and
-- before anything else. Otherwise unchanged.
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
    IF r.withdrawn_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_refused('WITHDRAWN', basalt_meta._withdrawn_hint(r.withdraw_reason));
    END IF;
    IF r.applied_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_refused('ALREADY_APPLIED', 'revert already applied');
    END IF;
    IF r.rejected_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_invalid('the person rejected this revert; nothing was reverted');
    END IF;
    IF r.signed_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_refused('ALREADY_SIGNED', 'revert already signed; the agent applies it in batches');
    END IF;
    IF r.expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'REVERT_EXPIRED',
            DETAIL = format('revert %s expired at %s; prepare it again', r.revert_id, r.expires_at);
    END IF;
    IF (r.binding_text::jsonb -> 'select') IS DISTINCT FROM basalt_meta._revert_select_text(r.selection) THEN
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
        IF EXISTS (SELECT 1 FROM basalt_meta.passkeys k
                    WHERE k.credential_id = p_credential_id AND k.revoked_at IS NOT NULL) THEN
            PERFORM basalt_meta._revert_refused('PASSKEY_REVOKED', 'passkey revoked');
        END IF;
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
        PERFORM basalt_meta._revert_refused('ROWS_CHANGED', 'rows changed since the preview; nothing was reverted, prepare the revert again');
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
               'resource', l -> 'resource', 'key', l -> 'key', 'rowHash', l -> 'rowHash',
               'conflict', l -> 'conflict', 'sqlState', l -> 'store' -> 'code')) ORDER BY n), '[]'::jsonb)
      INTO v_skipped
      FROM unnest(v_lines) WITH ORDINALITY u(t, n) CROSS JOIN LATERAL (SELECT u.t::jsonb AS l) j
     WHERE l ->> 'action' = 'SKIP';
    PERFORM basalt_meta._append(session_user, v_change, 'REVERTED', NULL, 'REVERT', NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', r.revert_id, 'scope', r.scope, 'scopeId', r.scope_id, 'select', r.selection,
                           'intent', r.intent, 'credentialId', encode(p_credential_id, 'hex'),
                           'binding', encode(r.binding, 'hex'), 'rows', v_rows, 'skipped', v_skipped));
    RETURN jsonb_build_object('changeId', v_change, 'rows', v_rows, 'skipped', cardinality(v_lines) - v_rows);
END $$;

-- The views gain the withdrawal, last; status reads WITHDRAWN for a
-- withdrawn request.
CREATE OR REPLACE VIEW basalt_meta.agent_approvals WITH (security_barrier = true) AS
    SELECT a.approval_id, a.run_id, a.task_id, a.intent, a.statement, a.params, a.assigned_columns, a.rows,
           CASE WHEN a.used_by_change IS NOT NULL THEN 'APPLIED'
                WHEN a.withdrawn_at IS NOT NULL THEN 'WITHDRAWN'
                WHEN a.expires_at <= pg_catalog.now() THEN 'EXPIRED'
                WHEN a.approved_at IS NOT NULL THEN 'APPROVED'
                ELSE 'PENDING' END AS status,
           a.created_at, a.expires_at, a.approved_at, a.binding_text, a.lines,
           a.withdrawn_at, a.withdraw_reason
      FROM basalt_meta.approvals a
     WHERE a.agent = session_user;

CREATE OR REPLACE VIEW basalt_meta.agent_reverts WITH (security_barrier = true) AS
    SELECT r.revert_id, r.scope, r.scope_id, CASE WHEN r.widened THEN NULL ELSE r.agents END AS agents,
           r.intent, r.rows, r.skipped,
           CASE WHEN r.applied_at IS NOT NULL THEN 'APPLIED'
                WHEN r.rejected_at IS NOT NULL THEN 'REJECTED'
                WHEN r.withdrawn_at IS NOT NULL THEN 'WITHDRAWN'
                WHEN r.signed_at IS NOT NULL AND r.apply_by > pg_catalog.now() THEN 'APPLYING'
                WHEN r.signed_at IS NOT NULL THEN 'EXPIRED'
                WHEN r.expires_at <= pg_catalog.now() THEN 'EXPIRED'
                ELSE 'PENDING' END AS status,
           r.created_at, r.expires_at, r.applied_at, r.change_id,
           CASE WHEN r.widened THEN NULL ELSE r.binding_text END AS binding_text,
           CASE WHEN r.widened THEN NULL ELSE r.lines END AS lines,
           r.batched, r.signed_at, r.apply_by, r.batches, p.restored, p.skipped AS skipped_now, p.pending,
           CASE WHEN r.widened THEN NULL
                ELSE pg_catalog.jsonb_build_object(
                    'scope', r.selection -> 'scope', 'scopeId', r.selection -> 'scopeId', 'runs', r.selection -> 'runs',
                    'resources', r.selection -> 'tables',
                    'agents', basalt_meta._selection_agents(r.selection -> 'agents')) END AS selection,
           r.widened, r.rejected_at, r.reject_note,
           r.withdrawn_at, r.withdraw_reason
      FROM basalt_meta.reverts r
      -- Inline, not _revert_progress: a view runs functions as its caller.
      LEFT JOIN LATERAL (SELECT count(l.line_no) FILTER (WHERE l.outcome = 'RESTORED')::int AS restored,
                                count(l.line_no) FILTER (WHERE l.outcome = 'SKIPPED')::int AS skipped,
                                count(l.line_no) FILTER (WHERE l.outcome = 'PENDING')::int AS pending
                           FROM basalt_meta.revert_lines l WHERE l.revert_id = r.revert_id) p ON r.batched
     WHERE r.requested_by = session_user;

-- The reason is the opener's text: only the opener sees it.
CREATE OR REPLACE VIEW basalt_meta.agent_plugin_approvals WITH (security_barrier = true) AS
    SELECT p.approval_id, p.name, p.instance,
           CASE WHEN p.status = 'PENDING' AND p.expires_at <= pg_catalog.clock_timestamp() THEN 'EXPIRED'
                ELSE p.status END AS status,
           p.opened_at, p.expires_at, p.approved_at,
           (session_user::text = ANY (p.agents)) AS names_caller,
           e.ended_at,
           p.detail,
           CASE WHEN p.opened_by = session_user THEN p.binding_text END AS binding_text,
           CASE WHEN p.opened_by = session_user THEN p.settings_text END AS settings_text,
           p.withdrawn_at,
           CASE WHEN p.opened_by = session_user THEN p.withdraw_reason END AS withdraw_reason
      FROM basalt_meta.plugin_approvals p
      LEFT JOIN basalt_meta.plugin_approval_ends e ON e.approval_id = p.approval_id AND e.agent = session_user
     WHERE session_user::text = ANY (p.agents) OR p.opened_by = session_user;

REVOKE ALL ON FUNCTION basalt_meta._check_withdraw_reason(text), basalt_meta._withdrawn_hint(text),
    basalt_meta.withdraw_approval(uuid, text), basalt_meta.withdraw_revert(uuid, text),
    basalt_meta.withdraw_plugin_approval(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION basalt_meta.withdraw_approval(uuid, text), basalt_meta.withdraw_revert(uuid, text),
    basalt_meta.withdraw_plugin_approval(uuid, text) TO {{agents}};
