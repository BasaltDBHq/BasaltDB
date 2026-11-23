package guard_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
)

// scopeTask is a task two agents ran in: bot changed leads 30 and 31 in two
// runs, and the helper changed lead 32 in its own run. The helper also has
// a run outside the task.
type scopeTask struct {
	d                *guardtest.DB
	bot, helper      *guardtest.Agent
	task             uuid.UUID
	botA, botB, help guard.Intent
	helperOutside    guard.Intent
}

func newScopeTask(t *testing.T) scopeTask {
	t.Helper()
	d := guardtest.New(t).WithDemo(t)
	all := append([]string{}, leads...)
	all = append(all, "public.lead_owner")
	e := scopeTask{d: d, bot: d.NewAgent(t, "bot", all, all), helper: d.NewAgent(t, "helper", all, all), task: uuid.Must(uuid.NewV7())}
	ctx := context.Background()
	start := func(a *guardtest.Agent, task uuid.UUID, text string) guard.Intent {
		in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), TaskID: task, Text: text}
		require.NoError(t, guard.StartRun(ctx, a.Conn, in))
		return in
	}
	e.botA = start(e.bot, e.task, "first part")
	e.botB = start(e.bot, e.task, "second part")
	e.help = start(e.helper, e.task, "helping")
	e.helperOutside = start(e.helper, uuid.Nil, "elsewhere")
	require.NoError(t, guardtest.Guarded(ctx, e.bot.Conn, e.botA, `UPDATE public.leads SET status = 'a' WHERE id = 30`))
	require.NoError(t, guardtest.Guarded(ctx, e.bot.Conn, e.botB, `UPDATE public.leads SET status = 'b' WHERE id = 31`,
		`UPDATE public.lead_owner SET owner = 'bot' WHERE id = 1`))
	require.NoError(t, guardtest.Guarded(ctx, e.helper.Conn, e.help, `UPDATE public.leads SET status = 'h' WHERE id = 32`,
		`UPDATE public.lead_owner SET owner = 'helper' WHERE id = 2`))
	require.NoError(t, guardtest.Guarded(ctx, e.helper.Conn, e.helperOutside, `UPDATE public.leads SET status = 'x' WHERE id = 33`))
	return e
}

func (e scopeTask) taskScope() action.Scope {
	return action.Scope{Kind: revert.ScopeTask, ID: e.task}
}

// scopeErrorText is err as the caller reads it (message, detail and hint),
// with id replaced, so two refusals of different ids compare byte for byte.
func scopeErrorText(t *testing.T, err error, ids ...uuid.UUID) string {
	t.Helper()
	var pg *pgconn.PgError
	require.ErrorAs(t, err, &pg)
	text := pg.Code + "|" + pg.Message + "|" + pg.Detail + "|" + pg.Hint
	for _, id := range ids {
		text = strings.ReplaceAll(text, id.String(), "<id>")
	}
	return text
}

// rawPreview calls preview_revert as the agent with a descriptor the agent
// wrote itself, skipping the Go client.
func rawPreview(c *pgx.Conn, sel string) error {
	rows, err := c.Query(context.Background(), `SELECT l FROM basalt_meta.preview_revert($1::jsonb) AS l`, sel)
	if err != nil {
		return err
	}
	rows.Close()
	return rows.Err()
}

func rawPrepare(c *pgx.Conn, sel string) error {
	_, err := c.Exec(context.Background(), `SELECT * FROM basalt_meta.prepare_revert($1::jsonb, 'x')`, sel)
	return err
}

// Another agent's change, run or task reads exactly like one that does not
// exist, on preview and prepare, through the Go client and straight to the
// functions (RS-1).
func TestRevertScopeOwnWorkOnly(t *testing.T) {
	t.Parallel()
	e := newScopeTask(t)
	ctx := context.Background()
	helperChange := changeIDOf(t, e.helper, e.helperOutside.RunID)
	unknown := uuid.Must(uuid.NewV7())
	cases := []struct {
		kind   revert.Scope
		theirs uuid.UUID
		detail string
	}{
		{revert.ScopeChange, helperChange, guardmodel.ScopeNotOwnChange},
		{revert.ScopeRun, e.helperOutside.RunID, guardmodel.ScopeNotOwnRun},
		{revert.ScopeTask, uuid.Must(uuid.NewV7()), guardmodel.ScopeNotOwnTask},
	}
	// The helper's own task, which bot never ran in.
	helperTask := uuid.Must(uuid.NewV7())
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), TaskID: helperTask, Text: "helper only"}
	require.NoError(t, guard.StartRun(ctx, e.helper.Conn, in))
	require.NoError(t, guardtest.Guarded(ctx, e.helper.Conn, in, `UPDATE public.leads SET status = 'y' WHERE id = 34`))
	cases[2].theirs = helperTask

	for _, tc := range cases {
		theirs := action.Scope{Kind: tc.kind, ID: tc.theirs}
		none := action.Scope{Kind: tc.kind, ID: unknown}
		_, errTheirs := guard.PreviewRevert(ctx, e.bot.Conn, theirs)
		requireScopeRefused(t, errTheirs, tc.detail)
		_, errNone := guard.PreviewRevert(ctx, e.bot.Conn, none)
		require.Equal(t, scopeErrorText(t, errNone, unknown), scopeErrorText(t, errTheirs, tc.theirs), "preview %s", tc.kind)

		_, errTheirs = guard.PrepareRevert(ctx, e.bot.Conn, theirs, "x")
		requireScopeRefused(t, errTheirs, tc.detail)
		_, errNone = guard.PrepareRevert(ctx, e.bot.Conn, none, "x")
		require.Equal(t, scopeErrorText(t, errNone, unknown), scopeErrorText(t, errTheirs, tc.theirs), "prepare %s", tc.kind)
	}
	require.Zero(t, count(t, e.d.Admin, `SELECT count(revert_id)::int FROM basalt_meta.reverts`), "nothing was stored")

	// Straight to the functions as the agent role, naming the other agent in
	// agents, or every agent: refused before anything is read.
	for _, agents := range []string{fmt.Sprintf(`[%q]`, e.helper.Role), `null`, fmt.Sprintf(`[%q, %q]`, e.bot.Role, e.helper.Role)} {
		sel := fmt.Sprintf(`{"scope": "TASK", "scopeId": %q, "agents": %s, "runs": null, "tables": null}`, e.task, agents)
		requireScopeRefused(t, rawPreview(e.bot.Conn, sel), guardmodel.ScopeFilter)
		requireScopeRefused(t, rawPrepare(e.bot.Conn, sel), guardmodel.ScopeFilter)
	}
	// A select naming another agent's work in its runs, under a task bot
	// never ran in, is refused for the task first: nothing about the run.
	sel := fmt.Sprintf(`{"scope": "TASK", "scopeId": %q, "agents": [%q], "runs": [%q], "tables": null}`, helperTask, e.bot.Role, in.RunID)
	requireScopeRefused(t, rawPreview(e.bot.Conn, sel), guardmodel.ScopeNotOwnTask)
}

// A task proposal holds only the caller's own lines, and the person-only
// path is not reachable from the agent role.
func TestRevertScopeTaskOwnLines(t *testing.T) {
	t.Parallel()
	e := newScopeTask(t)
	lines := previewRevert(t, e.bot.Conn, revert.ScopeTask, e.task)
	require.Len(t, lines, 3, "leads 30 and 31 and owner 1, not the helper's lead 32 or owner 2")
	for _, l := range lines {
		require.Nil(t, l.Conflict)
		require.NotEqual(t, `{"id":32}`, compact(t, l.Key))
	}
	prep, err := guard.PrepareRevert(context.Background(), e.bot.Conn, e.taskScope(), "Undo my part")
	require.NoError(t, err)
	b, err := revert.ParseBinding(prep.BindingText)
	require.NoError(t, err)
	require.Equal(t, revert.Select{Scope: revert.ScopeTask, ScopeID: e.task, Agents: []string{e.bot.Role}}, b.Select)
	require.False(t, b.Widened)
	require.Equal(t, 3, b.Rows)
	var widened bool
	var agents []string
	require.NoError(t, e.bot.Conn.QueryRow(context.Background(),
		`SELECT widened, agents::text[] FROM basalt_meta.agent_reverts WHERE revert_id = $1`, prep.RevertID).Scan(&widened, &agents))
	require.False(t, widened)
	require.Equal(t, []string{e.bot.Role}, agents)
}

// The runs and tables filters narrow the agent's own proposal, and refuse
// with one fixed text per kind whatever the reason (RS-1, owner Q11).
func TestRevertScopeFilters(t *testing.T) {
	t.Parallel()
	e := newScopeTask(t)
	ctx := context.Background()

	onlyB := e.taskScope()
	onlyB.Runs = []uuid.UUID{e.botB.RunID}
	lines, err := guard.PreviewRevert(ctx, e.bot.Conn, onlyB)
	require.NoError(t, err)
	require.Len(t, lines, 2, "lead 31 and owner 1, run B only")

	ownerOnly := onlyB
	ownerOnly.Tables = []string{"public.lead_owner"}
	lines, err = guard.PreviewRevert(ctx, e.bot.Conn, ownerOnly)
	require.NoError(t, err)
	require.Len(t, lines, 1)
	l, err := revert.ParseLine(lines[0])
	require.NoError(t, err)
	require.Equal(t, "public.lead_owner", l.Table)

	prep, err := guard.PrepareRevert(ctx, e.bot.Conn, ownerOnly, "Undo the owner only")
	require.NoError(t, err)
	b, err := revert.ParseBinding(prep.BindingText)
	require.NoError(t, err)
	require.Equal(t, []uuid.UUID{e.botB.RunID}, b.Select.Runs)
	require.Equal(t, []string{"public.lead_owner"}, b.Select.Tables)

	// Runs: the helper's run in the task, bot's run outside it and an
	// unknown run all read the same.
	botOutside := newRun(t, e.bot, "outside the task")
	runText := func(run uuid.UUID) string {
		s := e.taskScope()
		s.Runs = []uuid.UUID{run}
		_, err := guard.PreviewRevert(ctx, e.bot.Conn, s)
		requireScopeRefused(t, err, guardmodel.ScopeFilter)
		_, perr := guard.PrepareRevert(ctx, e.bot.Conn, s, "x")
		require.Equal(t, scopeErrorText(t, err, run), scopeErrorText(t, perr, run))
		return scopeErrorText(t, err, run)
	}
	unknownRun := runText(uuid.Must(uuid.NewV7()))
	require.Equal(t, unknownRun, runText(e.help.RunID))
	require.Equal(t, unknownRun, runText(botOutside.RunID))
	require.Contains(t, unknownRun, "run <id> is not one of your runs in task")

	// Tables: one the helper wrote in the task, an unguarded one and one
	// that does not exist all read the same.
	tableText := func(table string) string {
		s := e.taskScope()
		s.Tables = []string{table}
		_, err := guard.PreviewRevert(ctx, e.bot.Conn, s)
		requireScopeRefused(t, err, guardmodel.ScopeFilter)
		return strings.ReplaceAll(scopeErrorText(t, err), table, "<table>")
	}
	unknownTable := tableText("public.nope")
	require.Equal(t, unknownTable, tableText("public.payroll"))
	require.Equal(t, unknownTable, tableText("public.lead_notes"))
	require.Contains(t, unknownTable, "<table> has no change of yours in this scope")
	// lead_owner in run A: bot wrote it in the task (run B), so it is
	// inside the scope; a filter that leaves no line is NOTHING_TO_REVERT.
	empty := e.taskScope()
	empty.Runs = []uuid.UUID{e.botA.RunID}
	empty.Tables = []string{"public.lead_owner"}
	_, err = guard.PreviewRevert(ctx, e.bot.Conn, empty)
	requireCode(t, err, guardmodel.CodeNothingToRevert)
}

// The descriptor's shape is checked from the descriptor alone: the
// reserved store key, the caps, unknown and missing keys, runs outside a
// task.
func TestRevertScopeShape(t *testing.T) {
	t.Parallel()
	e := newScopeTask(t)
	runs := make([]string, revert.MaxFilter+1)
	tables := make([]string, revert.MaxFilter+1)
	for i := range runs {
		runs[i] = uuid.Must(uuid.NewV7()).String()
		tables[i] = fmt.Sprintf("public.t%d", i)
	}
	list := func(xs []string) string {
		b, err := json.Marshal(xs)
		require.NoError(t, err)
		return string(b)
	}
	base := func(scope, runs, tables string) string {
		return fmt.Sprintf(`{"scope": %q, "scopeId": %q, "agents": [%q], "runs": %s, "tables": %s}`, scope, e.task, e.bot.Role, runs, tables)
	}
	cases := map[string]struct{ sel, detail string }{
		"the reserved store key": {strings.Replace(base("TASK", "null", "null"), `{`, `{"store": "db1", `, 1), guardmodel.ScopeStoreReserved},
		"21 runs":                {base("TASK", list(runs), "null"), guardmodel.ScopeFilterCap},
		"21 tables":              {base("TASK", "null", list(tables)), guardmodel.ScopeFilterCap},
		"runs on a run scope":    {base("RUN", list(runs[:1]), "null"), guardmodel.ScopeShape},
		"an empty list":          {base("TASK", "[]", "null"), guardmodel.ScopeShape},
		"an unknown key":         {strings.Replace(base("TASK", "null", "null"), `{`, `{"database": "x", `, 1), guardmodel.ScopeShape},
		"a missing key":          {fmt.Sprintf(`{"scope": "TASK", "scopeId": %q, "agents": [%q], "runs": null}`, e.task, e.bot.Role), guardmodel.ScopeShape},
		"an unknown scope":       {base("DATABASE", "null", "null"), guardmodel.ScopeShape},
		"a bad run id":           {base("TASK", `["x"]`, "null"), guardmodel.ScopeShape},
		"a bad table name":       {base("TASK", "null", `["leads"]`), guardmodel.ScopeShape},
		"not an object":          {`[]`, guardmodel.ScopeShape},
	}
	for name, tc := range cases {
		err := rawPreview(e.bot.Conn, tc.sel)
		requireScopeRefused(t, err, tc.detail)
		require.Equal(t, tc.detail, func() string { d, _, _ := guard.ScopeRefusal(rawPrepare(e.bot.Conn, tc.sel)); return d }(), name)
	}
}

// The descriptor is normalized: the same choice is the same text.
func TestRevertScopeNormalized(t *testing.T) {
	t.Parallel()
	e := newScopeTask(t)
	sel := fmt.Sprintf(`{"tables": ["public.leads", "public.lead_owner", "public.leads"], "runs": [%q, %q], "agents": [%q], "scopeId": %q, "scope": "TASK"}`,
		strings.ToUpper(e.botB.RunID.String()), e.botA.RunID, e.bot.Role, strings.ToUpper(e.task.String()))
	var stored string
	err := e.bot.Conn.QueryRow(context.Background(), `SELECT binding_text FROM basalt_meta.prepare_revert($1::jsonb, 'x')`, sel).Scan(&stored)
	require.NoError(t, err)
	b, err := revert.ParseBinding(stored)
	require.NoError(t, err)
	want := []uuid.UUID{e.botA.RunID, e.botB.RunID}
	if want[0].String() > want[1].String() {
		want[0], want[1] = want[1], want[0]
	}
	require.Equal(t, revert.Select{
		Scope: revert.ScopeTask, ScopeID: e.task, Agents: []string{e.bot.Role}, Runs: want,
		Tables: []string{"public.lead_owner", "public.leads"},
	}, b.Select)
	require.Contains(t, stored, fmt.Sprintf(`"select": {"runs": [%q, %q], "scope": "TASK", "agents": [%q], "tables": ["public.lead_owner", "public.leads"], "scopeId": %q}`,
		want[0], want[1], e.bot.Role, e.task))
}

// A task the caller ran in with no line of its own: preview has nothing to
// revert, prepare stores an empty proposal for the person to widen, and
// apply_revert refuses to sign it.
func TestRevertScopeEmptyTaskProposal(t *testing.T) {
	t.Parallel()
	e := newScopeTask(t)
	ctx := context.Background()
	reader := guard.Intent{RunID: uuid.Must(uuid.NewV7()), TaskID: e.task, Text: "only reads"}
	other := e.d.NewAgent(t, "reader", leads, leads)
	require.NoError(t, guard.StartRun(ctx, other.Conn, reader))
	p := person(t, e.d)

	_, err := guard.PreviewRevert(ctx, other.Conn, e.taskScope())
	requireCode(t, err, guardmodel.CodeNothingToRevert)
	prep, err := guard.PrepareRevert(ctx, other.Conn, e.taskScope(), "Undo the task")
	require.NoError(t, err)
	require.Empty(t, prep.Lines)
	b, err := revert.Request{RevertID: prep.RevertID, Binding: prep.BindingText, Lines: prep.Lines}.Check()
	require.NoError(t, err, "the Go codec accepts the empty proposal")
	require.True(t, b.Empty())

	as, err := p.Sign(approval.Challenge(prep.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	_, err = guard.ApplyRevert(ctx, other.Conn, prep.RevertID, as)
	requireCode(t, err, guardmodel.CodeNothingToRevert)

	// A run or change scope with nothing to restore is never stored.
	_, err = guard.PrepareRevert(ctx, other.Conn, action.Scope{Kind: revert.ScopeRun, ID: reader.RunID}, "x")
	requireCode(t, err, guardmodel.CodeNothingToRevert)
}

// apply_revert checks the binding against the stored selection, refuses a
// rejected revert, and locks the revert row before any check.
func TestRevertScopeApplyChecks(t *testing.T) {
	t.Parallel()
	e := newScopeTask(t)
	ctx := context.Background()
	p := person(t, e.d)

	// A binding whose select is not the stored selection.
	prep, as := prepareSigned(t, e.bot, p, revert.ScopeRun, e.botA.RunID)
	e.d.Exec(t, `UPDATE basalt_meta.reverts SET binding_text = replace(binding_text, '"tables": null', '"tables": ["public.leads"]')
		WHERE revert_id = $1`, prep.RevertID)
	_, err := guard.ApplyRevert(ctx, e.bot.Conn, prep.RevertID, as)
	requireRevertInvalid(t, err, "does not carry this revert's scope")
	require.Equal(t, "a", leadStatus(t, e.d, 30))

	// A rejected revert cannot be signed.
	prep, as = prepareSigned(t, e.bot, p, revert.ScopeRun, e.botA.RunID)
	e.d.Exec(t, `UPDATE basalt_meta.reverts SET rejected_at = now() WHERE revert_id = $1`, prep.RevertID)
	require.Equal(t, "REJECTED", scalarOf[string](t, e.bot.Conn, `SELECT status FROM basalt_meta.agent_reverts WHERE revert_id = $1`, prep.RevertID))
	_, err = guard.ApplyRevert(ctx, e.bot.Conn, prep.RevertID, as)
	requireRevertInvalid(t, err, "rejected")

	// The row lock comes first: while another transaction holds the revert
	// row, apply_revert waits rather than checking a row that may change.
	prep, as = prepareSigned(t, e.bot, p, revert.ScopeRun, e.botA.RunID)
	holder, err := pgdial.Connect(ctx, e.d.URL)
	require.NoError(t, err)
	defer func() { _ = holder.Close(ctx) }()
	tx, err := holder.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `SELECT 1 FROM basalt_meta.reverts WHERE revert_id = $1 FOR UPDATE`, prep.RevertID)
	require.NoError(t, err)
	err = pgx.BeginFunc(ctx, e.bot.Conn, func(atx pgx.Tx) error {
		if _, err := atx.Exec(ctx, `SELECT set_config('lock_timeout', '200ms', true)`); err != nil {
			return err
		}
		_, err := guard.ApplyRevert(ctx, atx, prep.RevertID, as)
		return err
	})
	require.Equal(t, "55P03", guardtest.SQLState(err), "lock_not_available: apply waited on the revert row")
	require.NoError(t, tx.Rollback(ctx))
	out, err := guard.ApplyRevert(ctx, e.bot.Conn, prep.RevertID, as)
	require.NoError(t, err)
	require.Equal(t, 1, out.Rows)
	require.Equal(t, "open", leadStatus(t, e.d, 30))
}

// A table filter that leaves a change half selected restores only the
// selected table, and the change stays APPLIED (it was not wholly undone).
func TestRevertScopeTableFilterApplies(t *testing.T) {
	t.Parallel()
	e := newScopeTask(t)
	ctx := context.Background()
	p := person(t, e.d)
	s := action.Scope{Kind: revert.ScopeRun, ID: e.botB.RunID, Tables: []string{"public.lead_owner"}}
	prep, err := guard.PrepareRevert(ctx, e.bot.Conn, s, "Only the owner")
	require.NoError(t, err)
	as, err := p.Sign(approval.Challenge(prep.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	out, err := guard.ApplyRevert(ctx, e.bot.Conn, prep.RevertID, as)
	require.NoError(t, err)
	require.Equal(t, 1, out.Rows)
	require.Equal(t, "owner 1", scalarOf[string](t, e.d.Admin, `SELECT owner FROM public.lead_owner WHERE id = 1`))
	require.Equal(t, "b", leadStatus(t, e.d, 31), "the leads table was not selected")
	// Run B's two changes: the owner update is wholly undone, the leads
	// update was not selected and is not touched.
	require.Equal(t, "REVERTED", scalarOf[string](t, e.bot.Conn, `SELECT status FROM basalt_meta.agent_changes
		WHERE run_id = $1 AND table_name = 'public.lead_owner'`, e.botB.RunID))
	require.Equal(t, "APPLIED", scalarOf[string](t, e.bot.Conn, `SELECT status FROM basalt_meta.agent_changes
		WHERE run_id = $1 AND table_name = 'public.leads' AND reverted_by IS NULL`, e.botB.RunID))
}
