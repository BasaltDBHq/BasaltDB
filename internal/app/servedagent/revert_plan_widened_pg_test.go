package servedagent_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/revert/reverttest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// widenedPlanHelperRows is how many rows the helper changes in
// newWidenedPlan: with bot's ten, the widened revert is a large plan.
const widenedPlanHelperRows = revert.MaxLines + 10

// widenedPlan is a task where bot changed ids 1 to 10 of public.items and
// the helper many more, bot's revert of its own part, and the person's
// widen of it to the whole task (made as the page does, with a proof).
type widenedPlan struct {
	agentEnv
	revertID uuid.UUID
	binding  string
}

func newWidenedPlan(t *testing.T) widenedPlan {
	t.Helper()
	d := guardtest.New(t)
	ctx := context.Background()
	d.Exec(t, fmt.Sprintf(`CREATE TABLE public.items (id int PRIMARY KEY, v text NOT NULL);
		INSERT INTO public.items SELECT g, 'before' FROM generate_series(1, %d) g`, widenedPlanHelperRows+10))
	tables := []string{"public.items"}
	bot, helper := d.NewAgent(t, "bot", tables, tables), d.NewAgent(t, "helper", tables, tables)
	env := agentHarnessFor(t, d, bot, pageOrigin)
	task := uuid.Must(uuid.NewV7())
	start := func(a *guardtest.Agent) guard.Intent {
		in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), TaskID: task, Text: "bulk"}
		require.NoError(t, guard.StartRun(ctx, a.Conn, in))
		return in
	}
	require.NoError(t, guardtest.Guarded(ctx, bot.Conn, start(bot), `UPDATE public.items SET v = 'bot' WHERE id BETWEEN 1 AND 10`))
	stmts := make([]string, 0, widenedPlanHelperRows/10)
	for i := 10; i < widenedPlanHelperRows+10; i += 10 {
		stmts = append(stmts, fmt.Sprintf(`UPDATE public.items SET v = 'helper' WHERE id BETWEEN %d AND %d`, i+1, i+10))
	}
	require.NoError(t, guardtest.Guarded(ctx, helper.Conn, start(helper), stmts...))
	prep, err := guard.PrepareRevert(ctx, bot.Conn, action.Scope{Kind: revert.ScopeTask, ID: task}, "Undo the task")
	require.NoError(t, err)
	require.False(t, prep.Batched, "bot's own part is ten lines")

	every := revert.Select{Scope: revert.ScopeTask, ScopeID: task}
	selJSON, err := json.Marshal(every)
	require.NoError(t, err)
	var norm string
	var nonce []byte
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT basalt_meta._revert_select_norm($1::jsonb)::text`, string(selJSON)).Scan(&norm))
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT rescope_nonce FROM basalt_meta.reverts WHERE revert_id = $1`, prep.RevertID).Scan(&nonce))
	key, err := revert.RescopeKey([]byte("the page's new secret"))
	require.NoError(t, err)
	as, err := env.person.Sign(reverttest.RescopeChallenge(prep.RevertID, nonce, key, norm), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	out, err := guard.RescopeRevert(ctx, bot.Conn, action.RescopeRequest{RevertID: prep.RevertID, Select: every, Proof: &as, RescopeKey: key})
	require.NoError(t, err)
	b, err := revert.ParseBinding(out.BindingText)
	require.NoError(t, err)
	require.True(t, b.Batched && b.Widened)
	return widenedPlan{agentEnv: env, revertID: prep.RevertID, binding: out.BindingText}
}

// requireWidenedPlan checks a revert_plan answer for a widened plan: no
// scope or link, and the person told the agent cannot see what they added.
func requireWidenedPlan(t *testing.T, body map[string]any, status string) {
	t.Helper()
	require.Equal(t, status, body["status"], "%v", body)
	require.Equal(t, true, body["widened"])
	for _, key := range []string{"scope", "scopeId", "revertUrl", "links"} {
		require.NotContains(t, body, key)
	}
	require.Contains(t, str(t, body["personMessage"]), "You changed the scope on the signing page; the agent cannot see what you added.")
}

// A large plan the person widened: revert_plan lists every line number and
// outcome, the text only of bot's own lines, and no link while it waits
// for the signature. Once signed, the agent applies it by line number.
func TestRevertPlanOfAWidenedPlan(t *testing.T) {
	t.Parallel()
	e := newWidenedPlan(t)
	id := e.revertID.String()

	body, isError := e.h.call(t, "revert_plan", map[string]any{"revertId": id, "limit": 200})
	require.False(t, isError, "%v", body)
	requireWidenedPlan(t, body, "PENDING")
	requirePlanSteps(t, body, "PENDING")
	for _, s := range body["nextSteps"].([]any) {
		require.NotContains(t, s.(map[string]any), "url", "no link to the person's scope")
	}
	own, hidden := 0, 0
	for page := body; ; {
		for _, it := range items(t, page) {
			require.Contains(t, it, "line")
			require.Equal(t, "PENDING", it["outcome"])
			plan, ok := it["plan"].(map[string]any)
			if !ok {
				require.NotContains(t, it, "plan")
				hidden++
				continue
			}
			require.Contains(t, fmt.Sprint(plan["now"]), "bot", "a line of bot's own rows")
			own++
		}
		cursor, more := page["nextCursor"].(string)
		if !more {
			break
		}
		page, isError = e.h.call(t, "revert_plan", map[string]any{"revertId": id, "limit": 200, "cursor": cursor})
		require.False(t, isError, "%v", page)
	}
	require.Equal(t, 10, own, "bot's own lines keep their text")
	require.Equal(t, widenedPlanHelperRows, hidden, "the helper's lines show no text")

	as := signBinding(t, e.person, e.binding)
	_, err := guard.ApplyRevert(context.Background(), e.a.Conn, e.revertID, as)
	require.NoError(t, err)
	body, isError = e.h.call(t, "revert_plan", map[string]any{"revertId": id, "pending": true, "limit": 200})
	require.False(t, isError, "%v", body)
	requireWidenedPlan(t, body, "APPLYING")
	applyEveryBatch(t, e.h, id)
	body, isError = e.h.call(t, "revert_plan", map[string]any{"revertId": id})
	require.False(t, isError, "%v", body)
	requireWidenedPlan(t, body, "APPLIED")
	var left int
	require.NoError(t, e.d.Admin.QueryRow(context.Background(), `SELECT count(id)::int FROM public.items WHERE v <> 'before'`).Scan(&left))
	require.Zero(t, left, "every agent's rows were restored")
}

// A large plan the person rejected reads REJECTED, with the person's note
// and a STOP step.
func TestRevertPlanOfARejectedPlan(t *testing.T) {
	t.Parallel()
	e := newBatchEnv(t)
	_, err := guard.RejectRevert(context.Background(), e.a.Conn, e.prep.RevertID, "Not now.", nil)
	require.NoError(t, err)
	body, isError := e.h.call(t, "revert_plan", map[string]any{"revertId": e.prep.RevertID.String()})
	require.False(t, isError, "%v", body)
	require.Equal(t, "REJECTED", body["status"])
	requirePlanSteps(t, body, "REJECTED")
	require.Contains(t, str(t, body["personMessage"]), "Not now.")
	require.NotContains(t, body, "revertUrl")
}

// requirePlanSteps checks a revert_plan result against its catalog case
// (api/mcp/errors/next-steps.json).
func requirePlanSteps(t *testing.T, body map[string]any, kase string) {
	t.Helper()
	c, err := mcpcontract.LoadNextSteps()
	require.NoError(t, err)
	for _, r := range c.Results {
		if r.Tool == "revert_plan" && r.Case == kase {
			requireSteps(t, body, r.Steps, r.PersonMessage)
			return
		}
	}
	require.Failf(t, "no catalog case", "revert_plan %s", kase)
}
