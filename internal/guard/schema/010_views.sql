-- The only relations an agent role can SELECT. Each shows the calling
-- role its own rows (security_barrier); the raw tables expose values of
-- tables the agent cannot read.

-- The only objects an agent can SELECT (the raw ledger
-- exposes cascaded old values of tables the agent cannot read). Rows of
-- the calling agent only; row keys and values of tables the agent cannot
-- SELECT are redacted. security_barrier keeps the caller's own functions
-- from seeing rows before the filter.
CREATE VIEW basalt_meta.agent_runs WITH (security_barrier = true) AS
    SELECT r.run_id, r.task_id, r.agent, r.intent, r.started_at
      FROM basalt_meta.runs r
     WHERE r.agent = session_user;

-- The change records an agent sees: its own, with the approval each
-- applied under (or awaits), who acted (AGENT or PERSON), the revert a
-- revert change carries out, and the reverts of a change. Every agent whose
-- changes a revert covered sees the revert's change record, from the
-- selection; a selection of every agent (agents null) shows it to the
-- agents of the changes it covered.
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

-- The calling agent's ledger rows, row keys and values of tables it cannot
-- SELECT redacted, and redacted where a row names other agents' work
-- through a revert (RS-5). Two cases:
--   * a revert row (any kind whose detail names a revertId) of a revert
--     that is widened now, or whose select, oldSelect or droppedSelect
--     covered other agents' changes when it was written: REVERT_SIGNED,
--     REVERT_BATCH and REVERTED copy the skipped lines' tables and keys, and
--     REVERT_RESCOPED and REVERT_RESET the selects. It shows only
--     {revertId, widened, via};
--   * a ROW_CHANGE the change of a widened revert wrote for a row whose
--     reverted changes (revertOf) are not all the row's agent's: no table,
--     key, values or detail, and redacted.
-- Ids from details are cast to uuid only when they look like one, so the
-- lookups use the primary keys and one malformed value cannot fail the view.
CREATE OR REPLACE VIEW basalt_meta.agent_ledger WITH (security_barrier = true) AS
    SELECT l.seq, l.at, l.agent, l.change_id, l.kind,
           CASE WHEN NOT w.hide_row THEN l.table_name END AS table_name, l.op,
           CASE WHEN v.visible AND NOT w.hide_row THEN l.row_key END AS row_key,
           CASE WHEN v.visible AND NOT w.hide_row THEN l.old_row END AS old_row,
           CASE WHEN v.visible AND NOT w.hide_row THEN l.new_row END AS new_row,
           l.values_pruned, l.depth,
           CASE WHEN w.hide_revert
                THEN pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
                         'revertId', l.detail -> 'revertId', 'widened', true, 'via', l.detail -> 'via'))
                WHEN w.hide_row THEN pg_catalog.jsonb_build_object('widened', true)
                ELSE l.detail END AS detail,
           NOT v.visible OR w.hide_row AS redacted
      FROM basalt_meta.ledger l
      CROSS JOIN LATERAL (
          SELECT l.table_oid IS NULL
              OR coalesce(has_table_privilege(session_user, l.table_oid, 'SELECT'), false) AS visible
      ) v
      CROSS JOIN LATERAL (
          SELECT l.kind <> 'ROW_CHANGE' AND pg_catalog.jsonb_typeof(l.detail -> 'revertId') = 'string' AND (
                     EXISTS (SELECT 1 FROM basalt_meta.reverts r
                              WHERE r.widened
                                AND r.revert_id = CASE WHEN l.detail ->> 'revertId' ~ '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
                                                     THEN (l.detail ->> 'revertId')::uuid END)
                     OR EXISTS (
                     SELECT 1 FROM (VALUES (l.detail -> 'select'), (l.detail -> 'oldSelect'), (l.detail -> 'droppedSelect')) s(sel)
                      WHERE pg_catalog.jsonb_typeof(s.sel) = 'object'
                        AND (pg_catalog.jsonb_typeof(s.sel -> 'agents') IS DISTINCT FROM 'array'
                             OR EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements_text(s.sel -> 'agents') a
                                         WHERE a <> l.agent::text)))) AS hide_revert,
                 l.kind = 'ROW_CHANGE' AND pg_catalog.jsonb_typeof(l.detail -> 'revertOf') = 'array'
                 AND EXISTS (SELECT 1 FROM basalt_meta.changes c JOIN basalt_meta.reverts r ON r.revert_id = c.revert_id
                              WHERE c.change_id = l.change_id AND c.op = 'REVERT' AND r.widened)
                 AND EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements_text(l.detail -> 'revertOf') u(cid)
                              WHERE NOT EXISTS (SELECT 1 FROM basalt_meta.changes o
                                                 WHERE o.change_id = CASE WHEN u.cid ~ '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$' THEN u.cid::uuid END
                                                   AND o.agent = l.agent)) AS hide_row
      ) w
     WHERE l.agent = session_user;

-- Guarded tables the calling agent can SELECT: the tables whose rows the
-- engine can identify in a read (by primary key and xmin).
CREATE VIEW basalt_meta.agent_guarded_tables WITH (security_barrier = true) AS
    SELECT g.table_oid::oid AS table_oid,
           pg_catalog.format('%I.%I', n.nspname, c.relname) AS table_name, -- qualified whatever the search_path
           g.pk_cols
      FROM basalt_meta.guarded_tables g
      JOIN pg_catalog.pg_class c ON c.oid = g.table_oid
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE coalesce(pg_catalog.has_table_privilege(session_user, g.table_oid, 'SELECT'), false);

-- The calling agent's approvals and the passkeys' public data.
CREATE VIEW basalt_meta.agent_approvals WITH (security_barrier = true) AS
    SELECT a.approval_id, a.run_id, a.task_id, a.intent, a.statement, a.params, a.assigned_columns, a.rows,
           CASE WHEN a.used_by_change IS NOT NULL THEN 'APPLIED'
                WHEN a.expires_at <= pg_catalog.now() THEN 'EXPIRED'
                WHEN a.approved_at IS NOT NULL THEN 'APPROVED'
                ELSE 'PENDING' END AS status,
           a.created_at, a.expires_at, a.approved_at, a.binding_text, a.lines
      FROM basalt_meta.approvals a
     WHERE a.agent = session_user;

-- Active passkeys only, so links list only those; with their dates.
CREATE OR REPLACE VIEW basalt_meta.agent_passkeys AS
    SELECT k.credential_id, k.label, k.public_key_x, k.public_key_y, k.rp_id, k.origin, k.sign_count,
           k.created_at, k.last_used_at
      FROM basalt_meta.passkeys k
     WHERE k.revoked_at IS NULL;

-- A batched plan's lines, redacted after a widen (RS-5): a line's text
-- only when every change it names is the requesting role's. Numbers,
-- outcomes and conflicts stay, so the agent can still apply the signed
-- plan's batches.
CREATE OR REPLACE VIEW basalt_meta.agent_revert_lines WITH (security_barrier = true) AS
    SELECT l.revert_id, l.line_no,
           CASE WHEN NOT r.widened THEN l.line
                WHEN NOT EXISTS (
                    SELECT 1 FROM pg_catalog.jsonb_array_elements_text(
                                      coalesce(l.line::jsonb -> 'changeIds', '[null]'::jsonb)) u(cid)
                     WHERE NOT EXISTS (SELECT 1 FROM basalt_meta.changes c
                                        WHERE c.change_id = u.cid::uuid AND c.agent = r.requested_by))
                THEN l.line END AS line,
           l.outcome, l.conflict, l.sql_state, l.batch
      FROM basalt_meta.revert_lines l
      JOIN basalt_meta.reverts r ON r.revert_id = l.revert_id
     WHERE r.requested_by = session_user;

-- The calling agent role's setups and every UPGRADE: the engine confirms a
-- pending setup through it.
CREATE OR REPLACE VIEW basalt_meta.agent_setups WITH (security_barrier = true) AS
    SELECT s.setup_id, s.kind, s.guard_version, s.used_at
      FROM basalt_meta.setups s
     WHERE s.agent_role = session_user OR s.kind = 'UPGRADE';

-- The reverts the calling role prepared, with their status (REJECTED
-- included), the selection and widened. A revert widened beyond the role's
-- own work shows the role no binding, selection, agents or lines (RS-5).
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

-- Every engine row an agent role may read: keys and addresses are not
-- secrets, and the engine reads its own row here.
CREATE OR REPLACE VIEW basalt_meta.agent_engines WITH (security_barrier = true) AS
    SELECT e.engine_id, e.public_key, e.url, e.recorded_at, e.revoked_at
      FROM basalt_meta.engines e;

-- Every PIN_SET_ASIDE row of every agent: a reinstall concerns the whole
-- database, so every engine shows it. Chain heads, role names and the
-- Vault user's name, which the notice shows; no secrets.
CREATE OR REPLACE VIEW basalt_meta.agent_reinstalls WITH (security_barrier = true) AS
    SELECT l.at, l.agent,
           (l.detail->>'pinnedSeq')::bigint AS pinned_seq,
           pg_catalog.decode(l.detail->>'pinnedHash', 'hex') AS pinned_hash,
           (l.detail->>'pinnedInstall')::oid AS pinned_install,
           (l.detail->>'install')::oid AS install,
           (l.detail->>'installedAt')::timestamptz AS installed_at,
           (l.detail->>'installedBy') AS installed_by,
           (l.detail->>'vaultUser') AS vault_user
      FROM basalt_meta.ledger l
     WHERE l.kind = 'PIN_SET_ASIDE';
