package agent_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
)

// firstAgentCall is the first step the agent itself calls (CALL_TOOL), or
// false when the result has none.
func firstAgentCall(t *testing.T, body map[string]any) (string, map[string]any, bool) {
	t.Helper()
	steps, _ := body["nextSteps"].([]any)
	for _, raw := range steps {
		step, ok := raw.(map[string]any)
		require.True(t, ok, "%v", raw)
		if step["actor"] != "AGENT" || step["action"] != "CALL_TOOL" {
			continue
		}
		args, _ := step["arguments"].(map[string]any)
		return str(t, step["tool"]), args, true
	}
	return "", nil, false
}

// openLinkWithURL is the first link the person is asked to open, or "".
func openLinkWithURL(t *testing.T, body map[string]any) string {
	t.Helper()
	steps, _ := body["nextSteps"].([]any)
	for _, raw := range steps {
		step, ok := raw.(map[string]any)
		require.True(t, ok, "%v", raw)
		if step["action"] == "OPEN_LINK" {
			url, _ := step["url"].(string)
			return url
		}
	}
	return ""
}

// A large revert driven only by what the results say: the agent calls what
// CALL_TOOL says until there is none, and the person does what OPEN_LINK
// says, signing with a software passkey on the engine's local page.
func TestLargePlanLoopDrivenOnlyByTheSteps(t *testing.T) {
	t.Parallel()
	e := newBatchEnv(t, pageOrigin)
	p := newLocalPages(t, e.agentEnv)

	tool, args := "request_revert", map[string]any{"runId": e.runID.String(), "intent": "Undo the bulk update"}
	var visited []string
	signed := false
	for range 50 {
		body, isError := e.h.call(t, tool, args)
		require.False(t, isError, "%s %v: %v", tool, args, body)
		visited = append(visited, tool)
		kase := str(t, body["status"])
		if len(visited) == 1 {
			kase = "REQUESTED"
		}
		requireToolSteps(t, body, tool, kase)

		if link := openLinkWithURL(t, body); link != "" && !signed {
			id, secret := str(t, body["revertId"]), links.SecretOf(link)
			relayed := p.relayLater(id, secret, p.signRevertPage(id, secret, e.person), nil)
			require.Equal(t, http.StatusOK, <-relayed)
			signed = true
		}
		next, nextArgs, ok := firstAgentCall(t, body)
		if !ok {
			require.Equal(t, "APPLIED", body["status"], "the loop ends on the revert's end: %v", body)
			require.Equal(t, "STOP", lastAction(t, body))
			break
		}
		tool, args = next, nextArgs
	}
	require.True(t, signed, "the person was asked to sign")
	require.Equal(t, planRows, itemsLeft(t, e.d, "before"), "every row is restored")
	require.Zero(t, itemsLeft(t, e.d, "agent"))
	require.Equal(t, "request_revert", visited[0])
	require.Contains(t, visited, "revert_plan")
	require.Contains(t, visited, "apply_revert_batch")
	require.Equal(t, "apply_revert_batch", visited[len(visited)-1], "the last batch ends the revert")
}

func lastAction(t *testing.T, body map[string]any) string {
	t.Helper()
	steps, _ := body["nextSteps"].([]any)
	require.NotEmpty(t, steps)
	step, ok := steps[len(steps)-1].(map[string]any)
	require.True(t, ok)
	return str(t, step["action"])
}

// RLS_HIDES_ROWS appears only when a statement returns or changes no row on
// a table row-level security hides from the agent.
func TestRLSHidesRowsWarning(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	d.Exec(t, `CREATE TABLE public.vault (id int PRIMARY KEY, v text NOT NULL);
		INSERT INTO public.vault VALUES (1, 'a'), (2, 'b');
		ALTER TABLE public.vault ENABLE ROW LEVEL SECURITY`)
	tables := []string{"public.leads", "public.vault"}
	env := agentHarnessFor(t, d, d.NewAgent(t, "bot", tables, tables))

	warnings := func(body map[string]any) []any {
		w, _ := body["warnings"].([]any)
		return w
	}
	query := func(sql string) map[string]any {
		body, isError := env.h.call(t, "query", map[string]any{"sql": sql})
		require.False(t, isError, "%v", body)
		return body
	}

	hidden := query("SELECT id FROM public.vault")
	require.EqualValues(t, "0", hidden["rowCount"])
	require.Len(t, warnings(hidden), 1, "%v", hidden)
	w, ok := warnings(hidden)[0].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "RLS_HIDES_ROWS", w["code"])
	require.Equal(t, "public.vault", w["table"])
	require.NotEmpty(t, w["message"])
	require.Contains(t, str(t, w["personMessage"]), "public·vault", "a bare host's dot shows as a middle dot")
	steps := requireSteps(t, w, catalogWarning(t, "RLS_HIDES_ROWS").Steps, true)
	require.Equal(t, "basalt init --agent bot --agent-rls=all-rows", steps[1]["command"])

	require.Empty(t, warnings(query("SELECT id FROM public.leads WHERE id = -1")), "no rows, but RLS hides nothing there")
	require.NotEmpty(t, query("SELECT id FROM public.leads")["rows"])
	require.Empty(t, warnings(query("SELECT id FROM public.leads")), "rows came back")

	out, isError := env.h.call(t, "write", map[string]any{
		"sql": "UPDATE public.vault SET v = 'x' WHERE id = 1", "intent": "Fix the vault",
	})
	require.False(t, isError, "%v", out)
	require.EqualValues(t, "0", out["rows"], "the agent cannot see the row it asked to change")
	require.Len(t, warnings(out), 1, "%v", out)

	// Once the person lets the agent see every row, the cached answer is
	// forgotten by the next upkeep cycle and the warning goes away.
	d.Exec(t, `CREATE POLICY bot_all ON public.vault AS PERMISSIVE FOR ALL TO `+env.a.Role+` USING (true) WITH CHECK (true)`)
	require.Len(t, warnings(query("SELECT id FROM public.vault WHERE id = -1")), 1, "the answer is cached until the upkeep cycle")
	env.blind.Refresh()
	require.Empty(t, warnings(query("SELECT id FROM public.vault WHERE id = -1")))
}

func catalogWarning(t *testing.T, code string) mcpcontract.WarningSteps {
	t.Helper()
	c, err := mcpcontract.LoadNextSteps()
	require.NoError(t, err)
	for _, w := range c.Warnings {
		if w.Code == code {
			return w
		}
	}
	require.Failf(t, "no catalog warning", "%s", code)
	return mcpcontract.WarningSteps{}
}

// requireToolSteps checks body's nextSteps and personMessage against the
// catalog's result case of tool.
func requireToolSteps(t *testing.T, body map[string]any, tool, kase string) []map[string]any {
	t.Helper()
	c, err := mcpcontract.LoadNextSteps()
	require.NoError(t, err)
	for _, r := range c.Results {
		if r.Tool == tool && r.Case == kase {
			return requireSteps(t, body, r.Steps, r.PersonMessage)
		}
	}
	require.Failf(t, "no catalog case", "%s %s", tool, kase)
	return nil
}

// preview_revert tells the agent to ask the person, then request the revert
// of its change, run or task.
func TestPreviewRevertNextSteps(t *testing.T) {
	t.Parallel()
	env := agentHarness(t)
	run, isError := env.h.call(t, "run_start", map[string]any{"intent": "Win leads"})
	require.False(t, isError, "%v", run)
	runID, taskID := str(t, run["runId"]), str(t, run["taskId"])
	out, isError := env.h.call(t, "write", map[string]any{
		"sql": "UPDATE leads SET status = 'won' WHERE id IN (91, 92)", "intent": "They signed", "runId": runID,
	})
	require.False(t, isError, "%v", out)

	body, isError := env.h.call(t, "preview_revert", map[string]any{"runId": runID})
	require.False(t, isError, "%v", body)
	steps := requireToolSteps(t, body, "preview_revert", "PREVIEW")
	require.Equal(t, "request_revert", steps[1]["tool"])
	require.Equal(t, map[string]any{"runId": runID}, steps[1]["arguments"])

	// A task the agent ran in is its own scope (RS-1, RS-7): the agent
	// requests it, and the person can widen it on the signing page.
	body, isError = env.h.call(t, "preview_revert", map[string]any{"taskId": taskID})
	require.False(t, isError, "%v", body)
	steps = requireToolSteps(t, body, "preview_revert", "PREVIEW_TASK")
	require.Equal(t, "request_revert", steps[1]["tool"])
	require.Equal(t, map[string]any{"taskId": taskID}, steps[1]["arguments"])
	require.True(t, strings.HasSuffix(str(t, body["personMessage"]),
		" You can include other agents' changes in this task on the signing page."), "%v", body["personMessage"])
}
