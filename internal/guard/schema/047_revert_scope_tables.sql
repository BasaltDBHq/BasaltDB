-- The revert scope columns of reverts, and the agent views that show
-- them.

-- Idempotent, as every migration from version 16: running it again on a
-- guard that has it changes nothing.
ALTER TABLE basalt_meta.reverts
    ADD COLUMN IF NOT EXISTS selection        jsonb,
    ADD COLUMN IF NOT EXISTS proposed         jsonb,
    ADD COLUMN IF NOT EXISTS ceiling          jsonb,
    ADD COLUMN IF NOT EXISTS scope_token_hash bytea,
    ADD COLUMN IF NOT EXISTS rescope_nonce    bytea,
    ADD COLUMN IF NOT EXISTS rescoped         int NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS rejected_at      timestamptz,
    ADD COLUMN IF NOT EXISTS reject_note      text;

-- Once, while scope is still a plain column: the backfill and the expiry.
DO $$
DECLARE
    v_expired bigint;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_attribute a
                    WHERE a.attrelid = 'basalt_meta.reverts'::regclass AND a.attname = 'scope'
                      AND NOT a.attisdropped AND a.attgenerated = '') THEN
        RETURN;
    END IF;
    -- Every revert gets the scope it had, every run and table of its
    -- agents. Reverts from the M3-14 era whose agents name other roles
    -- come out widened.
    UPDATE basalt_meta.reverts r
       SET selection = jsonb_build_object(
               'scope', r.scope, 'scopeId', r.scope_id::text,
               'agents', basalt_meta._revert_select_list(to_jsonb(r.agents::text[])),
               'runs', NULL, 'tables', NULL),
           rescope_nonce = basalt_meta._revert_nonce();
    UPDATE basalt_meta.reverts r SET proposed = r.selection;
    -- Unsigned reverts expire: their bindings have no select, so they
    -- could no longer be signed and applied. A signed large plan keeps its
    -- lines and finishes as signed.
    UPDATE basalt_meta.reverts r SET expires_at = now()
     WHERE r.applied_at IS NULL AND r.signed_at IS NULL AND r.expires_at > now();
    GET DIAGNOSTICS v_expired = ROW_COUNT;
    IF v_expired > 0 THEN
        PERFORM basalt_meta._append(session_user, NULL, 'MIGRATION', NULL, NULL, NULL, NULL, NULL, NULL,
            jsonb_build_object('version', 20, 'revertsExpired', v_expired));
    END IF;
END $$;

ALTER TABLE basalt_meta.reverts
    ALTER COLUMN selection SET NOT NULL,
    ALTER COLUMN proposed SET NOT NULL,
    ALTER COLUMN rescope_nonce SET NOT NULL;

-- Every agent whose changes a revert covered sees the revert's change
-- record (version 7), now from the selection; a selection of every agent
-- (agents null) shows it to the agents of the changes it covered.
CREATE OR REPLACE VIEW basalt_meta.agent_changes WITH (security_barrier = true) AS
    SELECT c.change_id, c.at, c.agent, c.run_id, c.task_id, c.intent, c.op, c.table_name, c.statement,
           c.params, c.rows, c.cascaded_rows, c.duration_ms, c.status, c.code, c.reason, c.approval_id,
           c.actor_kind, c.revert_id, c.reverted_by
      FROM basalt_meta.changes c
     WHERE c.status <> 'PREVIEW'
       AND (c.agent = session_user
            OR (c.op = 'REVERT' AND EXISTS (
                SELECT 1 FROM basalt_meta.reverts r
                 WHERE r.revert_id = c.revert_id
                   AND (r.selection -> 'agents' ? session_user::text
                        OR (jsonb_typeof(r.selection -> 'agents') = 'null'
                            AND EXISTS (SELECT 1 FROM basalt_meta.changes x
                                         WHERE x.change_id = ANY (r.covered) AND x.agent = session_user))))));

DROP VIEW IF EXISTS basalt_meta.agent_reverts;
-- scope, scope_id and agents become generated from selection, so they
-- cannot disagree with it (once).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_attribute a
                    WHERE a.attrelid = 'basalt_meta.reverts'::regclass AND a.attname = 'scope'
                      AND NOT a.attisdropped AND a.attgenerated = '') THEN
        RETURN;
    END IF;
    ALTER TABLE basalt_meta.reverts DROP COLUMN scope, DROP COLUMN scope_id, DROP COLUMN agents;
    ALTER TABLE basalt_meta.reverts
        ADD COLUMN scope text GENERATED ALWAYS AS (selection ->> 'scope') STORED
            CONSTRAINT reverts_scope CHECK (scope IN ('CHANGE', 'RUN', 'TASK')),
        ADD COLUMN scope_id uuid GENERATED ALWAYS AS ((selection ->> 'scopeId')::uuid) STORED,
        ADD COLUMN agents name[] GENERATED ALWAYS AS (basalt_meta._revert_select_agents(selection)) STORED,
        ADD COLUMN widened boolean NOT NULL GENERATED ALWAYS AS (basalt_meta._widened(selection, requested_by)) STORED,
        ADD CONSTRAINT reverts_ceiling_token CHECK ((ceiling IS NULL) = (scope_token_hash IS NULL)),
        ADD CONSTRAINT reverts_reject_note CHECK (char_length(reject_note) <= 500);
END $$;

-- The reverts the calling role prepared (version 9), with REJECTED, the
-- selection and widened. A revert widened beyond the role's own work shows
-- the role no binding, selection, agents or lines (RS-5).
CREATE VIEW basalt_meta.agent_reverts WITH (security_barrier = true) AS
    SELECT r.revert_id, r.scope, r.scope_id, CASE WHEN r.widened THEN NULL ELSE r.agents END AS agents,
           r.intent, r.rows, r.skipped,
           CASE WHEN r.applied_at IS NOT NULL THEN 'APPLIED'
                WHEN r.rejected_at IS NOT NULL THEN 'REJECTED'
                WHEN r.signed_at IS NOT NULL AND r.apply_by > pg_catalog.now() THEN 'APPLYING'
                WHEN r.signed_at IS NOT NULL THEN 'EXPIRED'
                WHEN r.expires_at <= pg_catalog.now() THEN 'EXPIRED'
                ELSE 'PENDING' END AS status,
           r.created_at, r.expires_at, r.applied_at, r.change_id,
           CASE WHEN r.widened THEN NULL ELSE r.binding_text END AS binding_text,
           CASE WHEN r.widened THEN NULL ELSE r.lines END AS lines,
           r.batched, r.signed_at, r.apply_by, r.batches, p.restored, p.skipped AS skipped_now, p.pending,
           CASE WHEN r.widened THEN NULL ELSE r.selection END AS selection,
           r.widened, r.rejected_at, r.reject_note
      FROM basalt_meta.reverts r
      -- Inline, not _revert_progress: a view runs functions as its caller.
      LEFT JOIN LATERAL (SELECT count(l.line_no) FILTER (WHERE l.outcome = 'RESTORED')::int AS restored,
                                count(l.line_no) FILTER (WHERE l.outcome = 'SKIPPED')::int AS skipped,
                                count(l.line_no) FILTER (WHERE l.outcome = 'PENDING')::int AS pending
                           FROM basalt_meta.revert_lines l WHERE l.revert_id = r.revert_id) p ON r.batched
     WHERE r.requested_by = session_user;

GRANT SELECT ON basalt_meta.agent_reverts TO {{agents}};
