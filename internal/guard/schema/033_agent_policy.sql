-- Version 11 (M4, owner decision Nov 12 "Agent RLS"): basalt init may add
-- a policy that lets an agent see every row of a table it was granted,
-- only after the person confirmed it for that table. The ledger records
-- each one, chained like every other row.

-- Admin only (basalt init, right after its CREATE POLICY): record that the
-- person let p_agent see every row of p_table. Not granted to agents.
CREATE FUNCTION basalt_meta.record_agent_policy(p_agent name, p_table regclass, p_command text) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF p_command IS NULL OR p_command NOT IN ('SELECT', 'ALL') THEN
        PERFORM basalt_meta._invalid(format('command %s', p_command));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname = p_agent)
       OR NOT pg_has_role(p_agent, '{{agents}}', 'USAGE') THEN
        PERFORM basalt_meta._invalid(format('%s is not an agent role', p_agent));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy p
                    WHERE p.polrelid = p_table AND p.polname = p_agent
                      AND p_agent::regrole = ANY (p.polroles)) THEN
        PERFORM basalt_meta._invalid(format('no policy %s on %s', p_agent, p_table));
    END IF;
    RETURN basalt_meta._append(p_agent, NULL, 'AGENT_POLICY_ADDED', p_table, NULL, NULL, NULL, NULL, NULL,
        jsonb_build_object('policy', p_agent, 'command', p_command, 'by', session_user));
END $$;

REVOKE ALL ON FUNCTION basalt_meta.record_agent_policy(name, regclass, text) FROM PUBLIC;
