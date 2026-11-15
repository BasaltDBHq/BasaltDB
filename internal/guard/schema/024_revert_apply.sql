-- Applying a signed revert: apply_revert, and the commit trigger,
-- retention and agent_changes with reverts.

CREATE FUNCTION basalt_meta._revert_invalid(p_detail text) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'REVERT_INVALID', DETAIL = p_detail;
END $$;

-- Any relay (basalt revert, with the agent credential): the person's
-- passkey assertion over a prepared revert's binding. Verified and run in
-- one transaction, so there is no signed-but-unapplied revert to replay.
CREATE FUNCTION basalt_meta.apply_revert(
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

    -- Skipped rows as the preparing role saw them: no values, keys only of
    -- tables it can read.
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

-- At commit (version 4) without the write policy for reverts: a revert is
-- authorized by the person's signature and bypasses the row limits (D6),
-- and marking a change reverted is not a new action.
CREATE OR REPLACE FUNCTION basalt_meta._at_commit() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    c basalt_meta.changes;
BEGIN
    SELECT * INTO c FROM basalt_meta.changes WHERE change_id = NEW.change_id;
    IF NOT FOUND OR c.status NOT IN ('APPLIED', 'PREVIEW') OR c.op IN ('SELECT', 'REVERT') OR c.reverted_by IS NOT NULL THEN
        RETURN NULL;
    END IF;
    IF c.mode = 'PREVIEW' THEN
        RAISE EXCEPTION USING ERRCODE = 'BS006', MESSAGE = 'PREVIEW_CANNOT_COMMIT';
    END IF;
    IF c.approval_id IS NOT NULL THEN
        PERFORM basalt_meta._commit_approval(c);
    END IF;
    PERFORM basalt_meta._check_policy(c);
    RETURN NULL;
END $$;

-- Retention (version 4) plus reverts: their lines and binding text are
-- values (30 days); the rows go after 1 year.
CREATE OR REPLACE FUNCTION basalt_meta._prune(p_now timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    c_values_ttl constant interval := interval '30 days';
    c_meta_ttl   constant interval := interval '1 year';
    v_values  bigint := 0;
    v_rows    bigint := 0;
    v_expired bigint := 0;
    v_cut     bigint;
BEGIN
    UPDATE basalt_meta.changes c SET status = 'APPROVAL_EXPIRED'
      FROM basalt_meta.approvals a
     WHERE a.held_change = c.change_id AND c.status = 'APPROVAL_PENDING'
       AND a.used_by_change IS NULL AND a.expires_at <= p_now;
    GET DIAGNOSTICS v_expired = ROW_COUNT;

    UPDATE basalt_meta.ledger SET old_row = NULL, new_row = NULL, values_pruned = true
     WHERE NOT values_pruned AND at < p_now - c_values_ttl AND (old_row IS NOT NULL OR new_row IS NOT NULL);
    GET DIAGNOSTICS v_values = ROW_COUNT;
    UPDATE basalt_meta.changes SET params = NULL WHERE params IS NOT NULL AND at < p_now - c_values_ttl;
    UPDATE basalt_meta.approvals SET params = NULL, lines = NULL, binding_text = NULL, statement = NULL
     WHERE created_at < p_now - c_values_ttl AND (lines IS NOT NULL OR binding_text IS NOT NULL);
    UPDATE basalt_meta.reverts SET lines = NULL, binding_text = NULL
     WHERE created_at < p_now - c_values_ttl AND (lines IS NOT NULL OR binding_text IS NOT NULL);

    SELECT max(seq) INTO v_cut FROM basalt_meta.ledger WHERE at < p_now - c_meta_ttl;
    IF v_cut IS NOT NULL THEN
        UPDATE basalt_meta.chain_anchor a SET seq = l.seq, hash = l.hash
          FROM basalt_meta.ledger l WHERE a.id AND l.seq = v_cut;
        DELETE FROM basalt_meta.ledger WHERE seq <= v_cut;
        GET DIAGNOSTICS v_rows = ROW_COUNT;
        DELETE FROM basalt_meta.changes WHERE at < p_now - c_meta_ttl;
        DELETE FROM basalt_meta.runs WHERE started_at < p_now - c_meta_ttl;
        DELETE FROM basalt_meta.approvals WHERE created_at < p_now - c_meta_ttl;
        DELETE FROM basalt_meta.reverts WHERE created_at < p_now - c_meta_ttl;
    END IF;

    IF v_values + v_rows > 0 THEN
        PERFORM basalt_meta._append(session_user, NULL, 'PRUNED', NULL, NULL, NULL, NULL, NULL, NULL,
            jsonb_build_object('valuesPruned', v_values, 'rowsDeleted', v_rows));
    END IF;
    RETURN jsonb_build_object('valuesPruned', v_values, 'rowsDeleted', v_rows, 'approvalsExpired', v_expired);
END $$;

-- The change record gains who acted (AGENT or PERSON), the revert a
-- revert change carries out, and the reverts of a change. Every agent
-- whose changes a revert covered sees that revert's change record.
CREATE OR REPLACE VIEW basalt_meta.agent_changes WITH (security_barrier = true) AS
    SELECT c.change_id, c.at, c.agent, c.run_id, c.task_id, c.intent, c.op, c.table_name, c.statement,
           c.params, c.rows, c.cascaded_rows, c.duration_ms, c.status, c.code, c.reason, c.approval_id,
           c.actor_kind, c.revert_id, c.reverted_by
      FROM basalt_meta.changes c
     WHERE c.status <> 'PREVIEW'
       AND (c.agent = session_user
            OR (c.op = 'REVERT' AND EXISTS (SELECT 1 FROM basalt_meta.reverts r
                                             WHERE r.revert_id = c.revert_id AND session_user = ANY (r.agents))));

GRANT EXECUTE ON FUNCTION basalt_meta.apply_revert(uuid, bytea, bytea, bytea, bytea) TO {{agents}};
