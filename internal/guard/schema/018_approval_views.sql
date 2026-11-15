-- The agent views of approvals and passkeys.

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

CREATE VIEW basalt_meta.agent_passkeys AS
    SELECT k.credential_id, k.label, k.public_key_x, k.public_key_y, k.rp_id, k.origin, k.sign_count
      FROM basalt_meta.passkeys k;

-- The change record gains the approval it applied under (or awaits).
CREATE OR REPLACE VIEW basalt_meta.agent_changes WITH (security_barrier = true) AS
    SELECT c.change_id, c.at, c.agent, c.run_id, c.task_id, c.intent, c.op, c.table_name, c.statement,
           c.params, c.rows, c.cascaded_rows, c.duration_ms, c.status, c.code, c.reason, c.approval_id
      FROM basalt_meta.changes c
     WHERE c.agent = session_user AND c.status <> 'PREVIEW';

REVOKE ALL ON basalt_meta.passkeys, basalt_meta.approvals FROM PUBLIC;
GRANT SELECT ON basalt_meta.agent_approvals, basalt_meta.agent_passkeys TO {{agents}};
GRANT EXECUTE ON FUNCTION
    basalt_meta.preview_lines(text[]),
    basalt_meta.hold_action(text, jsonb, text[], text[]),
    basalt_meta.submit_approval(uuid, bytea, bytea, bytea, bytea)
TO {{agents}};
