-- The agent views after a widen: agent_ledger and agent_revert_lines.

-- Version 9's plan lines, redacted after a widen (RS-5): a line's text
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

-- Version 1's agent_ledger, redacted where a row names other agents' work
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

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA basalt_meta FROM PUBLIC;
GRANT EXECUTE ON FUNCTION basalt_meta.rescope_revert(uuid, jsonb, jsonb, bytea, bytea) TO {{agents}};
GRANT EXECUTE ON FUNCTION basalt_meta.reset_revert(uuid) TO {{agents}};
GRANT SELECT ON basalt_meta.agent_revert_lines, basalt_meta.agent_ledger TO {{agents}};
