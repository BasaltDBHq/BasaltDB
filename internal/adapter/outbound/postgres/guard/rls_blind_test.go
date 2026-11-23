package guard_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// agentCount counts the rows the agent sees in table.
func agentCount(t *testing.T, a *guardtest.Agent, table string) int {
	t.Helper()
	var n int
	// Plain SQL: test read as the agent.
	require.NoError(t, a.Conn.QueryRow(context.Background(), `SELECT count(id) FROM `+table).Scan(&n))
	return n
}

// TestRLSBlindTables: a table with RLS on and no policy for the agent role
// is reported, from the admin (naming the role) and from the agent itself;
// a policy for the role, for PUBLIC or for a role it inherits, or RLS off,
// clears it. Init never widens the agent's view (decision N12-7).
func TestRLSBlindTables(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	ctx := context.Background()
	tables := []string{"public.leads", "public.lead_notes"}
	a := d.NewAgent(t, "bot", leads, []string{"public.lead_notes"})

	blind, err := guard.RLSBlindTables(ctx, d.Admin, a.Role, tables)
	require.NoError(t, err)
	require.Empty(t, blind, "RLS off")

	d.Exec(t, `ALTER TABLE public.leads ENABLE ROW LEVEL SECURITY;
		ALTER TABLE public.lead_notes ENABLE ROW LEVEL SECURITY;
		ALTER TABLE public.payroll ENABLE ROW LEVEL SECURITY`)
	d.Init(t, guardmodel.AgentSpec{})
	require.Zero(t, agentCount(t, a, "public.leads"), "init adds no policy for the agent")
	require.Zero(t, agentCount(t, a, "public.lead_notes"))

	blind, err = guard.RLSBlindTables(ctx, d.Admin, a.Role, tables)
	require.NoError(t, err)
	require.Equal(t, []string{"public.lead_notes", "public.leads"}, blind, "the guard's own policy does not count")
	blind, err = guard.RLSBlindTables(ctx, a.Conn, "", nil)
	require.NoError(t, err)
	require.Equal(t, []string{"public.lead_notes", "public.leads"}, blind, "payroll is not the agent's")

	// A restrictive policy alone grants nothing; an INSERT-only one shows no rows.
	d.Exec(t, `CREATE POLICY r ON public.leads AS RESTRICTIVE FOR ALL TO `+a.Role+` USING (true);
		CREATE POLICY i ON public.leads FOR INSERT TO PUBLIC WITH CHECK (true)`)
	blind, err = guard.RLSBlindTables(ctx, d.Admin, a.Role, tables)
	require.NoError(t, err)
	require.Equal(t, []string{"public.lead_notes", "public.leads"}, blind)

	d.Exec(t, `CREATE POLICY s ON public.leads FOR SELECT TO `+a.Role+` USING (true);
		CREATE POLICY p ON public.lead_notes FOR ALL TO PUBLIC USING (true)`)
	blind, err = guard.RLSBlindTables(ctx, a.Conn, "", nil)
	require.NoError(t, err)
	require.Empty(t, blind)
	require.Equal(t, 200, agentCount(t, a, "public.leads"))

	d.Exec(t, `DROP POLICY p ON public.lead_notes;
		CREATE POLICY g ON public.lead_notes FOR SELECT TO `+d.Names.Agents()+` USING (true)`)
	blind, err = guard.RLSBlindTables(ctx, d.Admin, a.Role, tables)
	require.NoError(t, err)
	require.Empty(t, blind, "a policy for the agents group the role inherits")

	d.Exec(t, `DROP POLICY s ON public.leads; ALTER TABLE public.leads DISABLE ROW LEVEL SECURITY`)
	blind, err = guard.RLSBlindTables(ctx, d.Admin, a.Role, tables)
	require.NoError(t, err)
	require.Empty(t, blind)
}

// policiesOn lists "table policy command roles" for every policy.
func policiesOn(t *testing.T, d *guardtest.DB) []string {
	t.Helper()
	// Plain SQL: test catalog read.
	rows, err := d.Admin.Query(context.Background(), `SELECT format('%s %s %s %s', p.polrelid::regclass, p.polname, p.polcmd, p.polroles::regrole[])
		FROM pg_policy p ORDER BY 1`)
	require.NoError(t, err)
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	return out
}

// TestAgentPolicies: before the agent role exists, AgentBlindTables finds
// its RLS tables with their row counts; the policies the person confirmed
// let the agent see every row, are recorded in the ledger, are kept by
// re-init, touch no other table, and uninstall drops them (decision
// "Agent RLS", Nov 12).
func TestAgentPolicies(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	ctx := context.Background()
	d.Exec(t, `ALTER TABLE public.leads ENABLE ROW LEVEL SECURITY;
		ALTER TABLE public.lead_notes ENABLE ROW LEVEL SECURITY;
		ALTER TABLE public.payroll ENABLE ROW LEVEL SECURITY`)
	spec := guardmodel.AgentSpec{Name: "bot", Password: guard.NewPassword(), Write: leads, Read: []string{"public.lead_notes"}}

	blind, err := guard.AgentBlindTables(ctx, d.Admin, d.Names, spec)
	require.NoError(t, err)
	require.Equal(t, []guardmodel.BlindTable{{Table: "public.leads", Rows: 200, Write: true}, {Table: "public.lead_notes", Rows: 60}}, blind)

	s, err := guard.PlanInit(ctx, d.Admin, guardmodel.InitOptions{Names: d.Names, Agent: spec, AgentPolicies: blind})
	require.NoError(t, err)
	role, err := d.Names.Agent("bot")
	require.NoError(t, err)
	require.Contains(t, s.SQL(), "CREATE POLICY "+role+" ON public.leads AS PERMISSIVE FOR ALL TO "+role+" USING (true) WITH CHECK (true);")
	require.Contains(t, s.SQL(), "CREATE POLICY "+role+" ON public.lead_notes AS PERMISSIVE FOR SELECT TO "+role+" USING (true);")
	require.NoError(t, pgx.BeginFunc(ctx, d.Admin, func(tx pgx.Tx) error { return guard.ApplyScript(ctx, tx, s) }))

	dsn, err := guard.AgentConnString(d.URL, role, spec.Password)
	require.NoError(t, err)
	a := &guardtest.Agent{Role: role, Password: spec.Password, URL: dsn}
	a.Conn = a.Connect(t)
	require.Equal(t, 200, agentCount(t, a, "public.leads"))
	require.Equal(t, 60, agentCount(t, a, "public.lead_notes"))
	g := d.Names.Guard()
	require.ElementsMatch(t, []string{
		"lead_notes " + g + " * {" + g + "}",
		"lead_notes " + role + " r {" + role + "}",
		"leads " + g + " * {" + g + "}",
		"leads " + role + " * {" + role + "}",
	}, policiesOn(t, d), "payroll is not the agent's: untouched")

	// Plain SQL: test read of the agent's ledger view.
	rows, err := a.Conn.Query(ctx, `SELECT table_name || ' ' || (detail->>'command') FROM basalt_meta.agent_ledger
		WHERE kind = 'AGENT_POLICY_ADDED' ORDER BY seq`)
	require.NoError(t, err)
	events, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	require.Equal(t, []string{"public.leads ALL", "public.lead_notes SELECT"}, events)

	blind, err = guard.AgentBlindTables(ctx, d.Admin, d.Names, spec)
	require.NoError(t, err)
	require.Empty(t, blind, "re-init asks nothing more")
	spec.Password = guard.NewPassword()
	d.Init(t, spec)
	require.Len(t, policiesOn(t, d), 4, "re-init keeps them")

	_, err = d.Admin.Exec(ctx, `SELECT basalt_meta.record_agent_policy($1, 'public.payroll'::regclass, 'SELECT')`, role)
	require.Error(t, err, "no ledger row without the policy")

	require.NoError(t, a.Conn.Close(ctx))
	require.NoError(t, guard.Uninstall(ctx, d.Admin, d.Names))
	require.Empty(t, policiesOn(t, d))
}

// TestAgentBlindTablesOnlyTheAgentsTables: a table the agent role can
// already SELECT through a PUBLIC grant, with row-level security as its only
// barrier, is never offered for an agent policy when it is not in the
// agent's lists, whether its --read or its --write list is the empty one.
func TestAgentBlindTablesOnlyTheAgentsTables(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	ctx := context.Background()
	spec := guardmodel.AgentSpec{Name: "bot", Password: guard.NewPassword(), Write: leads}
	d.Init(t, spec)
	d.Exec(t, `ALTER TABLE public.leads ENABLE ROW LEVEL SECURITY;
		ALTER TABLE public.lead_notes ENABLE ROW LEVEL SECURITY;
		ALTER TABLE public.payroll ENABLE ROW LEVEL SECURITY;
		GRANT SELECT ON public.payroll TO PUBLIC`)

	blind, err := guard.AgentBlindTables(ctx, d.Admin, d.Names, spec)
	require.NoError(t, err)
	require.Equal(t, []guardmodel.BlindTable{{Table: "public.leads", Rows: 200, Write: true}}, blind, "no --read: payroll is not the agent's")

	spec = guardmodel.AgentSpec{Name: "bot", Password: guard.NewPassword(), Read: []string{"public.lead_notes"}}
	blind, err = guard.AgentBlindTables(ctx, d.Admin, d.Names, spec)
	require.NoError(t, err)
	require.Equal(t, []guardmodel.BlindTable{{Table: "public.lead_notes", Rows: 60}}, blind, "no --write: payroll is not the agent's")
}
