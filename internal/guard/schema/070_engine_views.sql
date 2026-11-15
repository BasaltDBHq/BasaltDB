-- The agent view of engines: agent_engines.

-- Every engine row an agent role may read: keys and addresses are not
-- secrets, and the engine reads its own row here.
CREATE OR REPLACE VIEW basalt_meta.agent_engines WITH (security_barrier = true) AS
    SELECT e.engine_id, e.public_key, e.url, e.recorded_at, e.revoked_at
      FROM basalt_meta.engines e;
REVOKE ALL ON basalt_meta.agent_engines FROM PUBLIC;
REVOKE ALL ON FUNCTION
    basalt_meta._engine_url_ok(text),
    basalt_meta._engine_id(bytea),
    basalt_meta._engine_refused(text, text),
    basalt_meta.record_engine(bytea, text),
    basalt_meta.revoke_engine(text)
FROM PUBLIC;
GRANT SELECT ON basalt_meta.agent_engines TO {{agents}};
