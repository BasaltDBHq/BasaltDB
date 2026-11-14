package guard

// Version 32 (owner decision Q-11): the catalog a proven rescope returns
// maps each change to its agent (CONTRACT.md, Rescope, widen and reject,
// "The agent of each row", and basalt_meta "Version 32"). A revert line
// names its changeIds but not their agents, so without it the page could
// tag rows only for a select of one agent.
//
// _revert_catalog keeps its signature, owner and grants: no EXECUTE for the
// agents group or PUBLIC. rescope_revert calls it only on the PROOF and
// SCOPE_TOKEN paths, with the ceiling, so the map reaches nobody else.
// Non-breaking: on an older guard the catalog only lacks changeAgents.
// Idempotent.
const v32CatalogChangeAgents = `
CREATE OR REPLACE FUNCTION basalt_meta._revert_catalog(p_sel jsonb) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    WITH s AS (SELECT c.change_id, c.agent, c.run_id FROM basalt_meta._revert_scope(p_sel) x
                 JOIN basalt_meta.changes c ON c.change_id = x.change_id)
    SELECT pg_catalog.jsonb_build_object(
        'agents', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('agent', a.agent, 'changes', a.n) ORDER BY a.agent::text COLLATE "C")
                              FROM (SELECT s.agent, pg_catalog.count(s.change_id)::int AS n FROM s GROUP BY s.agent) a), '[]'::jsonb),
        'runs', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                                     'runId', u.run_id, 'agent', u.agent, 'changes', u.n,
                                     'startedAt', pg_catalog.to_char(r.started_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
                                 ORDER BY u.run_id)
                            FROM (SELECT s.run_id, s.agent, pg_catalog.count(s.change_id)::int AS n FROM s
                                   WHERE s.run_id IS NOT NULL GROUP BY s.run_id, s.agent) u
                            JOIN basalt_meta.runs r ON r.run_id = u.run_id), '[]'::jsonb),
        'tables', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('table', t.table_name, 'rows', t.n) ORDER BY t.table_name COLLATE "C")
                              FROM (SELECT x.table_name, pg_catalog.count(x.seq)::int AS n FROM basalt_meta._revert_rows(p_sel) x
                                     GROUP BY x.table_name) t), '[]'::jsonb),
        -- Each change in the scope to the role that made it, so the page
        -- tags every row of a multi-agent select (Q-11).
        'changeAgents', coalesce((SELECT pg_catalog.jsonb_object_agg(s.change_id::text, s.agent::text) FROM s), '{}'::jsonb))
$$;
`
