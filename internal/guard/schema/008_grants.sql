-- What PUBLIC loses and the agents group may use in basalt_meta.

-- Agents: USAGE on the schema, SELECT on the three views, EXECUTE on the
-- validating functions. No INSERT, UPDATE or DELETE anywhere in basalt_meta
-- (D9) and no SELECT on its tables.
ALTER DEFAULT PRIVILEGES FOR ROLE {{guard}} REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
REVOKE ALL ON SCHEMA basalt_meta FROM PUBLIC;
GRANT USAGE ON SCHEMA basalt_meta TO {{agents}};
REVOKE ALL ON ALL TABLES IN SCHEMA basalt_meta FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA basalt_meta FROM PUBLIC;
GRANT SELECT ON basalt_meta.agent_runs, basalt_meta.agent_changes, basalt_meta.agent_ledger TO {{agents}};
GRANT EXECUTE ON FUNCTION
    basalt_meta.start_run(uuid, uuid, text),
    basalt_meta.finish_change(text, text, jsonb, int),
    basalt_meta.record_refusal(uuid, uuid, text, text, text, jsonb, text, text, int),
    basalt_meta.record_event(text, uuid, jsonb),
    basalt_meta.prune(),
    basalt_meta.verify_chain(),
    basalt_meta.chain_head(),
    basalt_meta.check_head(bigint, bytea),
    basalt_meta.uncovered_tables()
TO {{agents}};
