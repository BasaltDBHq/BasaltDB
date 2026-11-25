package guard_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// guardPolicies lists the tables carrying the guard's RLS policy.
func guardPolicies(t *testing.T, d *guardtest.DB) []string {
	t.Helper()
	rows, err := d.Admin.Query(context.Background(), `SELECT p.polrelid::regclass::text FROM pg_policy p
		WHERE p.polname = $1 ORDER BY 1`, d.Names.Guard())
	require.NoError(t, err)
	var out []string
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		out = append(out, s)
	}
	require.NoError(t, rows.Err())
	return out
}

// TestInitAddsGuardPolicyOnRLSTables: basalt init gives the guard role a
// permissive policy on every guarded table with RLS enabled (agent-writable
// and cascade targets), only those, again on re-init, and uninstall drops
// it (decision N12-7).
func TestInitAddsGuardPolicyOnRLSTables(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	ctx := context.Background()
	d.Exec(t, `ALTER TABLE public.leads ENABLE ROW LEVEL SECURITY;
		ALTER TABLE public.lead_notes ENABLE ROW LEVEL SECURITY;
		ALTER TABLE public.payroll ENABLE ROW LEVEL SECURITY`)
	a := d.NewAgent(t, "bot", leads, leads)
	require.Equal(t, []string{"lead_notes", "leads"}, guardPolicies(t, d), "payroll is not guarded; note_tags has no RLS")

	var roles []string
	var cmd string
	var permissive bool
	var using, check string
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT p.polroles::regrole[]::text[], p.polcmd::text, p.polpermissive,
			pg_get_expr(p.polqual, p.polrelid), pg_get_expr(p.polwithcheck, p.polrelid)
		FROM pg_policy p WHERE p.polname = $1 AND p.polrelid = 'public.leads'::regclass`, d.Names.Guard()).
		Scan(&roles, &cmd, &permissive, &using, &check))
	require.Equal(t, []string{d.Names.Guard()}, roles)
	require.Equal(t, "*", cmd)
	require.True(t, permissive)
	require.Equal(t, "true", using)
	require.Equal(t, "true", check)

	uncovered, err := guard.UncoveredTables(ctx, a.Conn)
	require.NoError(t, err)
	require.Empty(t, uncovered)

	// A table that turns RLS on later is reported until the next init.
	d.Exec(t, `ALTER TABLE public.note_tags ENABLE ROW LEVEL SECURITY`)
	uncovered, err = guard.UncoveredTables(ctx, a.Conn)
	require.NoError(t, err)
	require.Len(t, uncovered, 1)
	require.Equal(t, "note_tags", uncovered[0].Table)
	require.Equal(t, "RLS_WITHOUT_GUARD_POLICY", uncovered[0].Why)

	d.Init(t, guardmodel.AgentSpec{})
	d.Init(t, guardmodel.AgentSpec{}) // idempotent
	require.Equal(t, []string{"lead_notes", "leads", "note_tags"}, guardPolicies(t, d))
	uncovered, err = guard.UncoveredTables(ctx, a.Conn)
	require.NoError(t, err)
	require.Empty(t, uncovered)

	require.NoError(t, a.Conn.Close(ctx))
	require.NoError(t, guard.Uninstall(ctx, d.Admin, d.Names))
	require.Empty(t, guardPolicies(t, d))
}

// rlsDemo: leads with RLS on and a policy letting agents see and write
// leads 1 to 100 only; lead_notes with RLS on and no policy for agents.
func rlsDemo(t *testing.T) (*guardtest.DB, *guardtest.Agent) {
	t.Helper()
	d := guardtest.New(t).WithDemo(t)
	d.Exec(t, `ALTER TABLE public.leads ENABLE ROW LEVEL SECURITY;
		ALTER TABLE public.lead_notes ENABLE ROW LEVEL SECURITY`)
	a := d.NewAgent(t, "bot", leads, leads)
	d.Exec(t, fmt.Sprintf(`CREATE POLICY agents_first_hundred ON public.leads TO %s
		USING (id <= 100) WITH CHECK (id <= 100)`, d.Names.Agents()))
	return d, a
}

// TestRevertRestoresRowsHiddenFromGuardBefore: with the policy the guard
// sees and restores rows of RLS tables, an update and the rows a delete
// cascaded into a table the agent cannot see, which M3 skipped as ROW_GONE.
func TestRevertRestoresRowsHiddenFromGuardBefore(t *testing.T) {
	t.Parallel()
	d, a := rlsDemo(t)
	p := person(t, d)
	ctx := context.Background()
	in := newRun(t, a, "Clean up leads")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id = 85`))
	approvedWrite(t, a, p, in, `DELETE FROM public.leads WHERE id = $1`, []any{3}, []string{})
	require.Zero(t, count(t, d.Admin, `SELECT count(1)::int FROM public.lead_notes WHERE lead_id = 3`))

	lines := previewRevert(t, a.Conn, revert.ScopeRun, in.RunID)
	for _, l := range lines {
		require.Equal(t, revert.ActionRestore, l.Action, "%+v", l)
	}
	out := revertScope(t, a, p, revert.ScopeRun, in.RunID)
	require.Zero(t, out.Skipped)
	require.Equal(t, "open", leadStatus(t, d, 85))
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(1)::int FROM public.leads WHERE id = 3`))
	require.Equal(t, 2, count(t, d.Admin, `SELECT count(1)::int FROM public.lead_notes WHERE lead_id = 3`))
	require.Equal(t, 2, count(t, d.Admin, `SELECT count(1)::int FROM public.note_tags WHERE note_id IN (5, 6)`))
	require.Nil(t, guardVerify(t, d))
}

// TestAgentRLSUnchanged: the guard's policy names only the guard role, so
// the agent still sees and writes only the rows its own policies allow,
// and revert lines do not show it values of rows those policies may hide
// (decision N12-8).
func TestAgentRLSUnchanged(t *testing.T) {
	t.Parallel()
	d, a := rlsDemo(t)
	p := person(t, d)
	ctx := context.Background()
	d.Exec(t, fmt.Sprintf(`GRANT SELECT ON public.lead_notes TO %s`, a.Role))

	require.Equal(t, 100, count(t, a.Conn, `SELECT count(1)::int FROM public.leads`))
	require.Zero(t, count(t, a.Conn, `SELECT count(1)::int FROM public.lead_notes`))
	var member, bypass bool
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT pg_has_role($1, $2, 'MEMBER'), r.rolbypassrls
		FROM pg_roles r WHERE r.rolname = $1`, a.Role, d.Names.Guard()).Scan(&member, &bypass))
	require.False(t, member)
	require.False(t, bypass)

	in := newRun(t, a, "Score leads")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET score = 9 WHERE id IN (50, 51, 150)`))
	require.Equal(t, 0, count(t, d.Admin, `SELECT count(1)::int FROM public.leads WHERE id = 150 AND score = 9`))
	approvedWrite(t, a, p, in, `DELETE FROM public.leads WHERE id = $1`, []any{4}, []string{})

	// A person moves lead 51 out of the agent's view.
	d.Exec(t, `UPDATE public.leads SET id = 251 WHERE id = 51`)

	lines := previewRevert(t, a.Conn, revert.ScopeRun, in.RunID)
	require.Len(t, lines, 7) // leads 50, 51, 4, the two notes of lead 4 and their tags
	own := lineFor(t, lines, "public.leads", `{"id":50}`)
	require.False(t, own.Redacted, "the agent's own RESTORE line shows its values")
	require.Equal(t, revert.ActionRestore, own.Action)
	redacted := 0
	for _, l := range lines {
		if !l.Redacted {
			continue
		}
		redacted++
		require.Empty(t, l.Key)
		require.Empty(t, l.Now)
		require.NotEmpty(t, l.RowHash)
	}
	require.Equal(t, 5, redacted, "the skipped lead 51, the cascaded notes (RLS) and tags (no SELECT)")

	// Another agent that can read leads under the same policy cannot
	// preview bot's run at all (RS-1): it reads like a run that does not
	// exist.
	other := d.NewAgent(t, "auditor", nil, leads)
	_, err := guard.PreviewRevert(ctx, other.Conn, action.Scope{Kind: revert.ScopeRun, ID: in.RunID})
	requireScopeRefused(t, err, guard.ScopeNotOwnRun)
	require.Equal(t, 98, count(t, other.Conn, `SELECT count(1)::int FROM public.leads`), "1 to 100 without the deleted 4 and the moved 51")
}
