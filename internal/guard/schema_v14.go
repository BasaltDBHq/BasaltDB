package guard

// Version 14: list_runs pages an agent's own runs by run id (keyset on
// run_id within agent_runs, which filters on agent = session_user). runs
// had only its primary key and started_at, so the per-agent keyset needs
// its own index. IF NOT EXISTS keeps the step idempotent.
const v14RunsAgent = `
CREATE INDEX IF NOT EXISTS runs_agent ON basalt_meta.runs (agent, run_id);
`
