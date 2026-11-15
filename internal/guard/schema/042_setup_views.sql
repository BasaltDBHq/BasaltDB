-- The agent view of setups: agent_setups.

-- The calling agent role's setups and every UPGRADE: the engine confirms a
-- pending setup through it.
CREATE OR REPLACE VIEW basalt_meta.agent_setups WITH (security_barrier = true) AS
    SELECT s.setup_id, s.kind, s.guard_version, s.used_at
      FROM basalt_meta.setups s
     WHERE s.agent_role = session_user OR s.kind = 'UPGRADE';

REVOKE ALL ON basalt_meta.agent_setups FROM PUBLIC;
REVOKE ALL ON FUNCTION
    basalt_meta._setup_refused(text, text),
    basalt_meta.record_setup(uuid, text, name, int, timestamptz)
FROM PUBLIC;
GRANT SELECT ON basalt_meta.agent_setups TO {{agents}};
