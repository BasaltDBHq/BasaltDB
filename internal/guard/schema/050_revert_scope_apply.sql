-- apply_revert over a scope descriptor.

-- Any relay (version 9): verify the person's assertion over a prepared
-- revert and run it in the same call; for a batched plan, record the
-- signature only. The revert row is locked before any check, so a rescope
-- and a signature cannot interleave. The binding must carry the stored
-- selection as its select, and the lines are recomputed from that
-- selection, never from the binding.
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
    IF r.rejected_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_invalid('the person rejected this revert; nothing was reverted');
    END IF;
    IF r.signed_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_invalid('revert already signed; the agent applies it in batches');
    END IF;
    IF r.expires_at <= now() THEN
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

-- The last batch of a plan (version 9): as there, and a covered change
-- becomes REVERTED only when no table filter left one of its rows out.
CREATE OR REPLACE FUNCTION basalt_meta._revert_finish(r basalt_meta.reverts, p_batches int) RETURNS void
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
           status = CASE WHEN coalesce(v.all_restored, true) AND basalt_meta._revert_whole(r.selection, c.change_id)
                         THEN 'REVERTED' ELSE c.status END
      FROM covered v
     WHERE c.change_id = v.cid AND (v.any_restored OR v.all_restored IS NULL);
    PERFORM basalt_meta._append(session_user, r.change_id, 'REVERTED', NULL, 'REVERT', NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', r.revert_id, 'scope', r.scope, 'scopeId', r.scope_id, 'intent', r.intent,
                           'rows', v_progress.restored, 'skipped', v_progress.skipped, 'batches', p_batches));
END $$;

-- The (scope, id) forms are replaced by the descriptor forms above.
DROP FUNCTION IF EXISTS basalt_meta.preview_revert(text, uuid);
DROP FUNCTION IF EXISTS basalt_meta.prepare_revert(text, uuid, text);
DROP FUNCTION IF EXISTS basalt_meta._revert_items(text, uuid, boolean);
DROP FUNCTION IF EXISTS basalt_meta._revert_chain_list(text, uuid);
DROP FUNCTION IF EXISTS basalt_meta._revert_chains(text, uuid);
DROP FUNCTION IF EXISTS basalt_meta._revert_chains_walk(text, uuid);
DROP FUNCTION IF EXISTS basalt_meta._revert_scope(text, uuid);

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA basalt_meta FROM PUBLIC;
GRANT EXECUTE ON FUNCTION basalt_meta.preview_revert(jsonb) TO {{agents}};
GRANT EXECUTE ON FUNCTION basalt_meta.prepare_revert(jsonb, text) TO {{agents}};
