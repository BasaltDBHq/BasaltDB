-- Privileges. PUBLIC gets nothing in basalt_meta. The agents group gets
-- USAGE on the schema, SELECT on the agent views and EXECUTE on the
-- validating functions; no INSERT, UPDATE or DELETE anywhere in
-- basalt_meta.

REVOKE ALL ON SCHEMA basalt_meta FROM PUBLIC;
GRANT USAGE ON SCHEMA basalt_meta TO {{agents}};
REVOKE ALL ON ALL TABLES IN SCHEMA basalt_meta FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA basalt_meta FROM PUBLIC;

-- The agent views, and the installed schema version, which the engine
-- reads on every agent tool call.
GRANT SELECT ON basalt_meta.agent_runs, basalt_meta.agent_changes, basalt_meta.agent_ledger TO {{agents}};
GRANT SELECT ON basalt_meta.agent_guarded_tables TO {{agents}};
GRANT SELECT ON basalt_meta.agent_approvals, basalt_meta.agent_passkeys TO {{agents}};
GRANT SELECT ON basalt_meta.agent_reverts TO {{agents}};
GRANT SELECT ON basalt_meta.agent_revert_lines TO {{agents}};
GRANT SELECT ON basalt_meta.schema_version TO {{agents}};
GRANT SELECT ON basalt_meta.agent_pii_columns, basalt_meta.agent_pii_catalog TO {{agents}};
GRANT SELECT ON basalt_meta.agent_setups TO {{agents}};
GRANT SELECT ON basalt_meta.agent_engines TO {{agents}};
GRANT SELECT ON basalt_meta.agent_reinstalls TO {{agents}};

-- The session, the chain and coverage.
GRANT EXECUTE ON FUNCTION
    basalt_meta.start_run(uuid, uuid, text),
    basalt_meta.finish_change(text, text, jsonb, int),
    basalt_meta.record_refusal(uuid, uuid, text, text, text, jsonb, text, text, int),
    basalt_meta.record_event(text, uuid, jsonb),
    basalt_meta.prune(),
    basalt_meta.verify_chain(),
    basalt_meta.chain_head(),
    basalt_meta.check_head(bigint, bytea),
    basalt_meta.uncovered_tables() TO {{agents}};
GRANT EXECUTE ON FUNCTION basalt_meta.verify_chain_from(bigint, bytea) TO {{agents}};
GRANT EXECUTE ON FUNCTION basalt_meta.record_read(uuid, text, jsonb, text[], int, int, jsonb) TO {{agents}};

-- Approvals and their reveal.
GRANT EXECUTE ON FUNCTION basalt_meta.preview_lines(text[]), basalt_meta.hold_action(text, jsonb, text[], text[]), basalt_meta.submit_approval(uuid, bytea, bytea, bytea, bytea) TO {{agents}};
GRANT EXECUTE ON FUNCTION basalt_meta.open_reveal(uuid, jsonb, bytea), basalt_meta.reveal_approval_rows(uuid, bytea) TO {{agents}};

-- Reverts and their reveal.
GRANT EXECUTE ON FUNCTION basalt_meta.preview_revert(jsonb) TO {{agents}};
GRANT EXECUTE ON FUNCTION basalt_meta.prepare_revert(jsonb, text) TO {{agents}};
GRANT EXECUTE ON FUNCTION basalt_meta.apply_revert(uuid, bytea, bytea, bytea, bytea) TO {{agents}};
GRANT EXECUTE ON FUNCTION basalt_meta.apply_revert_batch(uuid, int[]) TO {{agents}};
GRANT EXECUTE ON FUNCTION basalt_meta.rescope_revert(uuid, jsonb, jsonb, bytea, bytea) TO {{agents}};
GRANT EXECUTE ON FUNCTION basalt_meta.reset_revert(uuid) TO {{agents}};
GRANT EXECUTE ON FUNCTION basalt_meta.revert_nonce(uuid) TO {{agents}};
GRANT EXECUTE ON FUNCTION basalt_meta.reject_revert(uuid, text, bytea) TO {{agents}};
GRANT EXECUTE ON FUNCTION basalt_meta.reveal_nonce(text, uuid), basalt_meta.reveal_revert_rows(uuid, jsonb, bytea) TO {{agents}};

-- PII classification.
GRANT EXECUTE ON FUNCTION basalt_meta.pii_readable_columns(), basalt_meta.pii_fingerprint(), basalt_meta.pii_unclassified() TO {{agents}};

-- Reinstalls.
GRANT EXECUTE ON FUNCTION basalt_meta.install_id(), basalt_meta.record_pin_set_aside(bigint, bytea, uuid),
    basalt_meta.pin_on_chain(bigint, bytea) TO {{agents}};
