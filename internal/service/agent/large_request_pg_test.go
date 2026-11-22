package agent_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
)

// largeRequestEnv is an agent whose table docs has a row with a 2 MB body
// (a revert of an UPDATE to it carries that value in its lines) and 20 rows
// of 60 000 '<' (a held DELETE of them carries 1.2 MB of lines). Both are
// past what a page decodes from a link.
func largeRequestEnv(t *testing.T, pagesOrigin ...string) agentEnv {
	t.Helper()
	d := guardtest.New(t)
	d.Exec(t, fmt.Sprintf(`CREATE TABLE public.docs (id int PRIMARY KEY, body text);
		INSERT INTO public.docs VALUES (1, repeat('x', %d)), (2, 'two');
		INSERT INTO public.docs SELECT g, repeat('<', 60000) FROM generate_series(101, 120) g`, bigValue))
	tables := []string{"public.docs"}
	return agentHarnessFor(t, d, d.NewAgent(t, "bot", tables, tables), pagesOrigin...)
}

func steps(t *testing.T, body map[string]any) []map[string]any {
	t.Helper()
	list, ok := body["nextSteps"].([]any)
	require.True(t, ok, "%v", body)
	out := make([]map[string]any, 0, len(list))
	for _, s := range list {
		m, ok := s.(map[string]any)
		require.True(t, ok)
		out = append(out, m)
	}
	return out
}

func actions(t *testing.T, body map[string]any) []string {
	t.Helper()
	all := steps(t, body)
	out := make([]string, 0, len(all))
	for _, s := range all {
		out = append(out, str(t, s["action"]))
	}
	return out
}

// TestAHeldWriteTooLargeForALink: a held DELETE of rows with 1.2 MB of
// values is held, not refused for its size (its preview lines are not
// charged to the call), and with no local pages and no Vault it is REQUEST_TOO_LARGE:
// no link, the setup change, then list_pending with reissueLink.
// list_pending restates it with the page's address and the same steps,
// within the budget.
func TestAHeldWriteTooLargeForALink(t *testing.T) {
	t.Parallel()
	e := largeRequestEnv(t)
	body, isError := e.h.call(t, "write", map[string]any{"sql": "DELETE FROM public.docs WHERE id > 100", "intent": "Drop the large docs"})
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "REQUEST_TOO_LARGE", "")
	approval, ok := body["approval"].(map[string]any)
	require.True(t, ok, "%v", body)
	require.NotContains(t, approval, "approvalUrl", "no link can carry it")
	require.NotContains(t, approval, "requestFile")
	require.Contains(t, body["personMessage"], "local pages")
	require.Equal(t, []string{"ASK_PERSON", "END_TURN", "CALL_TOOL"}, actions(t, body))
	call := steps(t, body)[2]
	require.Equal(t, "list_pending", call["tool"])
	args, ok := call["arguments"].(map[string]any)
	require.True(t, ok, "%v", call)
	require.Equal(t, true, args["reissueLink"])
	runID := str(t, args["runId"])

	page := callFits(t, e.h, "list_pending", map[string]any{"runId": runID})
	item := items(t, page)[0]
	require.Equal(t, "http://localhost:8787/approvals/"+str(t, approval["approvalId"]), item["approvalUrl"],
		"the page's address with no fragment")
	require.NotContains(t, item, "requestFile")
	require.Equal(t, []string{"ASK_PERSON", "END_TURN", "CALL_TOOL"}, actions(t, item))
}

// TestAHeldWriteTooLargeForALinkGetsTheLocalShortLink: with the local
// pages, the same hold hands over a short link, whose page fetches the
// request from the engine.
func TestAHeldWriteTooLargeForALinkGetsTheLocalShortLink(t *testing.T) {
	t.Parallel()
	e := largeRequestEnv(t, "http://localhost:7878")
	body, isError := e.h.call(t, "write", map[string]any{"sql": "DELETE FROM public.docs WHERE id > 100", "intent": "Drop the large docs"})
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "HELD", "")
	approval, ok := body["approval"].(map[string]any)
	require.True(t, ok)
	require.True(t, strings.HasPrefix(str(t, approval["approvalUrl"]), "http://localhost:7878/approvals/"))
	require.Contains(t, approval["approvalUrl"], "#s=")
}

// TestARevertTooLargeForALink: request_revert of a run that wrote a 2 MB
// value prepares the revert, and with no local pages answers QUERY_TIMEOUT
// REQUEST_TOO_LARGE naming it, with a STOP first and request_revert with
// reissueLink last. With the local pages it hands over a short link.
func TestARevertTooLargeForALink(t *testing.T) {
	t.Parallel()
	for _, pages := range []string{"", "http://localhost:7878"} {
		e := largeRequestEnv(t, pages)
		ctx := context.Background()
		in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Shorten"}
		require.NoError(t, guard.StartRun(ctx, e.a.Conn, in))
		require.NoError(t, guardtest.Guarded(ctx, e.a.Conn, in, `UPDATE public.docs SET body = 'short' WHERE id = 1`))
		body, isError := e.h.call(t, "request_revert", map[string]any{"runId": in.RunID.String(), "intent": "Undo"})
		if pages != "" {
			require.False(t, isError, "%v", body)
			require.Contains(t, body["revertUrl"], "#s=")
			continue
		}
		requireToolError(t, body, isError, "QUERY_TIMEOUT", "REQUEST_TOO_LARGE", "")
		require.Equal(t, []string{"STOP", "ASK_PERSON", "END_TURN", "CALL_TOOL"}, actions(t, body))
		call := steps(t, body)[3]
		args, ok := call["arguments"].(map[string]any)
		require.True(t, ok)
		require.Equal(t, true, args["reissueLink"])
		require.Contains(t, body["message"], str(t, args["revertId"]))
		require.Contains(t, body["personMessage"], "narrower revert")
	}
}

// TestAWaitReadsEachPollOnItsOwnBudget: a wait polls the revert many times;
// each poll is charged to a budget of its own, so lines of about 620 KB read on
// every poll never add up to SIZE_LIMIT on the call.
func TestAWaitReadsEachPollOnItsOwnBudget(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.notes (id int PRIMARY KEY, body text);
		INSERT INTO public.notes SELECT g, repeat('x', 1500) FROM generate_series(1, 200) g`)
	tables := []string{"public.notes"}
	e := agentHarnessFor(t, d, d.NewAgent(t, "bot", tables, tables), "http://localhost:7878")
	ctx := context.Background()
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Rewrite"}
	require.NoError(t, guard.StartRun(ctx, e.a.Conn, in))
	stmts := make([]string, 0, 20)
	for i := range 20 {
		stmts = append(stmts, fmt.Sprintf(`UPDATE public.notes SET body = repeat('y', 1500) WHERE id BETWEEN %d AND %d`, i*10+1, i*10+10))
	}
	require.NoError(t, guardtest.Guarded(ctx, e.a.Conn, in, stmts...))
	body, isError := e.h.call(t, "request_revert", map[string]any{"runId": in.RunID.String(), "intent": "Undo"})
	require.False(t, isError, "%v", body)
	body, isError = e.h.call(t, "request_revert", map[string]any{"revertId": str(t, body["revertId"]), "waitForSignature": 3})
	require.False(t, isError, "the wait ends PENDING, not SIZE_LIMIT: %v", body)
	require.Equal(t, "PENDING", body["status"])
}
