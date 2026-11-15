-- The agent views: agent_runs, agent_changes and agent_ledger.

-- The only objects an agent can SELECT (the raw ledger
-- exposes cascaded old values of tables the agent cannot read). Rows of
-- the calling agent only; row keys and values of tables the agent cannot
-- SELECT are redacted. security_barrier keeps the caller's own functions
-- from seeing rows before the filter.
CREATE VIEW basalt_meta.agent_runs WITH (security_barrier = true) AS
    SELECT r.run_id, r.task_id, r.agent, r.intent, r.started_at
      FROM basalt_meta.runs r
     WHERE r.agent = session_user;

CREATE VIEW basalt_meta.agent_changes WITH (security_barrier = true) AS
    SELECT c.change_id, c.at, c.agent, c.run_id, c.task_id, c.intent, c.op, c.table_name, c.statement,
           c.params, c.rows, c.cascaded_rows, c.duration_ms, c.status, c.code, c.reason
      FROM basalt_meta.changes c
     WHERE c.agent = session_user AND c.status <> 'PREVIEW';

CREATE VIEW basalt_meta.agent_ledger WITH (security_barrier = true) AS
    SELECT l.seq, l.at, l.agent, l.change_id, l.kind, l.table_name, l.op,
           CASE WHEN v.visible THEN l.row_key END AS row_key,
           CASE WHEN v.visible THEN l.old_row END AS old_row,
           CASE WHEN v.visible THEN l.new_row END AS new_row,
           l.values_pruned, l.depth, l.detail, NOT v.visible AS redacted
      FROM basalt_meta.ledger l
      CROSS JOIN LATERAL (
          SELECT l.table_oid IS NULL
              OR coalesce(has_table_privilege(session_user, l.table_oid, 'SELECT'), false) AS visible
      ) v
     WHERE l.agent = session_user;
