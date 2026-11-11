package guard_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
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
	d.Init(t, guard.AgentSpec{})
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
