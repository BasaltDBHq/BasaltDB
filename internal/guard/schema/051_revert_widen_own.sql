-- Version 21 (RS-2, RS-5): the person's widen proof in Postgres
-- (CONTRACT.md, basalt_meta "Version 21"). rescope_revert
-- changes a pending revert's scope: inside the requesting role's own work
-- with no proof while nobody widened it, beyond it only with the person's
-- passkey proof over a single-use nonce and the hash of a key derived from
-- the page's new link secret, and after a widen only with the scope token
-- that proof returned. reset_revert puts a revert back to the agent's
-- proposal. Also: an undo of a widened revert is not the agent's own
-- change, agent_revert_lines and agent_ledger redact what the person added,
-- and a task proposal is looked up by (task_id, agent).

-- The task proposal's lookup by (task_id, agent), so its cost does not grow
-- with other agents' changes in the task (that growth would be a timing signal).
CREATE INDEX IF NOT EXISTS changes_task_agent ON basalt_meta.changes (task_id, agent, change_id);

-- Version 20's _revert_scope, with a TASK of listed agents looked up by
-- (task_id, agent) in its own statement, so the index above serves it.
CREATE OR REPLACE FUNCTION basalt_meta._revert_scope(p_sel jsonb) RETURNS TABLE (change_id uuid, agent name)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_id     uuid := (p_sel ->> 'scopeId')::uuid;
    v_agents name[] := basalt_meta._revert_select_agents(p_sel);
BEGIN
    IF p_sel ->> 'scope' = 'TASK' AND v_agents IS NOT NULL THEN
        RETURN QUERY SELECT c.change_id, c.agent FROM basalt_meta.changes c
         WHERE c.task_id = v_id AND c.agent = ANY (v_agents)
           AND c.mode = 'APPLY' AND c.status IN ('APPLIED', 'REVERTED')
           AND c.op IN ('INSERT', 'UPDATE', 'DELETE', 'REVERT')
           AND (jsonb_typeof(p_sel -> 'runs') IS DISTINCT FROM 'array' OR (p_sel -> 'runs') ? c.run_id::text);
        RETURN;
    END IF;
    RETURN QUERY SELECT c.change_id, c.agent FROM basalt_meta.changes c
     WHERE c.mode = 'APPLY' AND c.status IN ('APPLIED', 'REVERTED')
       AND c.op IN ('INSERT', 'UPDATE', 'DELETE', 'REVERT')
       AND CASE p_sel ->> 'scope' WHEN 'CHANGE' THEN c.change_id = v_id
                                  WHEN 'RUN' THEN c.run_id = v_id
                                  ELSE c.task_id = v_id END
       AND (v_agents IS NULL OR c.agent = ANY (v_agents))
       AND (jsonb_typeof(p_sel -> 'runs') IS DISTINCT FROM 'array' OR (p_sel -> 'runs') ? c.run_id::text);
END $$;

-- Why the normalized descriptor p_sel is not p_role's own work (RS-1), as
-- {detail, hint}, or NULL when it is: agents exactly [p_role], its own
-- change or run or a task it ran in, every listed run and table inside
-- that work. Version 20's _revert_own_select checks, as a yes or no that
-- raises nothing, so rescope_revert can ask without answering. One fixed
-- text per kind: another agent's change, run or table reads like one that
-- does not exist.
--
-- The change of a widened revert (op REVERT, recorded under the role that
-- relayed it) is not the role's own: undoing it would show the role the
-- other agents' rows and old values the person added (RS-5).
CREATE OR REPLACE FUNCTION basalt_meta._revert_own_refusal(p_sel jsonb, p_role name) RETURNS text[]
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_id      uuid := (p_sel ->> 'scopeId')::uuid;
    v_own     jsonb := p_sel || jsonb_build_object('runs', NULL, 'tables', NULL);
    v_refused text[];
BEGIN
    IF p_sel -> 'agents' IS DISTINCT FROM jsonb_build_array(p_role::text) THEN
        RETURN ARRAY['FILTER', 'agents is exactly your own role: an agent proposes only its own work'];
    END IF;
    CASE p_sel ->> 'scope'
    WHEN 'CHANGE' THEN
        IF NOT EXISTS (SELECT 1 FROM basalt_meta.changes c
                        WHERE c.change_id = v_id AND c.agent = p_role
                          AND NOT (c.op = 'REVERT' AND EXISTS (SELECT 1 FROM basalt_meta.reverts r
                                                                WHERE r.revert_id = c.revert_id AND r.widened))) THEN
            RETURN ARRAY['NOT_OWN_CHANGE', format('change %s is not one of your changes', v_id)];
        END IF;
    WHEN 'RUN' THEN
        IF NOT EXISTS (SELECT 1 FROM basalt_meta.runs r WHERE r.run_id = v_id AND r.agent = p_role) THEN
            RETURN ARRAY['NOT_OWN_RUN', format('run %s is not one of your runs', v_id)];
        END IF;
    ELSE
        IF NOT EXISTS (SELECT 1 FROM basalt_meta.runs r WHERE r.task_id = v_id AND r.agent = p_role) THEN
            RETURN ARRAY['NOT_OWN_TASK', format('you have no run in task %s', v_id)];
        END IF;
    END CASE;
    v_refused := ARRAY(
        SELECT format('run %s is not one of your runs in task %s', u.run, v_id)
          FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(p_sel -> 'runs') = 'array' THEN p_sel -> 'runs' ELSE '[]' END) u(run)
         WHERE NOT EXISTS (SELECT 1 FROM basalt_meta.runs r
                            WHERE r.run_id = u.run::uuid AND r.task_id = v_id AND r.agent = p_role)
        UNION ALL
        SELECT format('%s has no change of yours in this scope', u.tbl)
          FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(p_sel -> 'tables') = 'array' THEN p_sel -> 'tables' ELSE '[]' END) u(tbl)
         WHERE NOT EXISTS (SELECT 1 FROM basalt_meta._revert_rows(v_own) x WHERE x.table_name = u.tbl));
    IF cardinality(v_refused) > 0 THEN
        RETURN ARRAY['FILTER', array_to_string(v_refused, '; ')];
    END IF;
    RETURN NULL;
END $$;

-- Version 20's check for preview_revert and prepare_revert, now through
-- _revert_own_refusal: the same texts, and an undo of a widened revert is
-- NOT_OWN_CHANGE.
CREATE OR REPLACE FUNCTION basalt_meta._revert_own_select(p jsonb) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_sel     jsonb := basalt_meta._revert_select_norm(p);
    v_refusal text[] := basalt_meta._revert_own_refusal(v_sel, session_user);
BEGIN
    IF v_refusal IS NOT NULL THEN
        PERFORM basalt_meta._scope_refused(v_refusal[1], v_refusal[2]);
    END IF;
    RETURN v_sel;
END $$;
