package agent_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/links/linkstest"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/revert/reverttest"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver/mcptest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// winLeads starts a run and sets leads ids to won through MCP, as the
// agent does; it returns the run id and the write's change id.
func winLeads(t *testing.T, h harness, ids string) (string, string) {
	t.Helper()
	run, isError := h.call(t, "run_start", map[string]any{"intent": "Win leads"})
	require.False(t, isError, "%v", run)
	runID := str(t, run["runId"])
	out, isError := h.call(t, "write", map[string]any{
		"sql": "UPDATE leads SET status = 'won' WHERE id IN (" + ids + ")", "intent": "They signed", "runId": runID,
	})
	require.False(t, isError, "%v", out)
	return runID, str(t, out["changeId"])
}

func TestRequestRevertOfARunWithTheLocalPages(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	env := agentHarnessFor(t, d, d.NewAgent(t, "bot", leads, leads), pageOrigin)
	p := newLocalPages(t, env)
	runID, _ := winLeads(t, env.h, "71, 72, 73")
	d.Exec(t, `UPDATE public.leads SET status = 'person' WHERE id = 73`)

	body, isError := env.h.call(t, "request_revert", map[string]any{"runId": runID, "intent": "Undo yesterday's lead status merge."})
	require.False(t, isError, "%v", body)
	id := str(t, body["revertId"])
	require.Equal(t, "PENDING", body["status"])
	require.Equal(t, "RUN", body["scope"])
	require.Equal(t, runID, body["scopeId"])
	require.Equal(t, "Undo yesterday's lead status merge.", body["intent"])
	require.Equal(t, false, body["batched"])
	require.EqualValues(t, "2", body["rows"])
	require.EqualValues(t, "1", body["skipped"])
	require.NotEmpty(t, body["expiresAt"])
	link := str(t, body["revertUrl"])
	steps := requireResultSteps(t, body, "REQUESTED")
	require.Equal(t, link, steps[0]["url"])
	require.Equal(t, "request_revert", steps[1]["tool"])
	require.Equal(t, map[string]any{"revertId": id, "waitForSignature": json.Number("90")}, steps[1]["arguments"])
	secret := linkstest.SecretOf(link)
	require.Len(t, secret, 22, "a 128-bit secret")
	require.Equal(t, pageOrigin+"/reverts/"+id+"#s="+secret, link)
	msg := str(t, body["personMessage"])
	require.True(t, strings.HasPrefix(msg, "Revert of run "+runID+": 2 rows to restore, 1 left as they are "+
		"(changed after the agent). Why: Undo yesterday's lead status merge. Expires "), msg)
	require.True(t, strings.HasSuffix(msg, "\nSign it with your passkey here:\n\n"+link), msg)
	mcptest.Require(t, msg, mcptest.LinksOf(t, body))
	require.Equal(t, []toolresult.Link{{Label: "Review and sign the revert", URL: link}}, mcptest.LinksOf(t, body))
	require.Equal(t, "won", leadStatus(t, d, 71), "a request reverts nothing")

	// The short link's secret opens the request; a wrong one is an
	// unknown id.
	var perr pageError
	require.Equal(t, http.StatusNotFound, p.get("/api/v1/reverts/"+id, strings.Repeat("A", len(secret)), &perr))
	require.Equal(t, "NOT_FOUND", perr.Code)
	var req revert.Request
	require.Equal(t, http.StatusOK, p.get("/api/v1/reverts/"+id, secret, &req))
	b, err := req.Check()
	require.NoError(t, err)
	require.Equal(t, "Undo yesterday's lead status merge.", b.Intent, "the agent's intent is in the binding the person signs")

	// The person signs on the page and the page relays it.
	as, err := env.person.Sign(approval.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	signed, err := json.Marshal(reverttest.NewResponse(b.RevertID, as))
	require.NoError(t, err)
	var out action.AppliedRevert
	require.Equal(t, http.StatusOK, p.post("/api/v1/reverts/"+id+"/apply", pageOrigin, secret, signed, &out))
	require.Equal(t, 2, out.Rows)
	require.Equal(t, "open", leadStatus(t, d, 71))
	require.Equal(t, "person", leadStatus(t, d, 73), "people win")
}

func TestRequestRevertOfAChangeWithoutLocalPages(t *testing.T) {
	t.Parallel()
	env := agentHarness(t)
	_, changeID := winLeads(t, env.h, "74, 75")

	body, isError := env.h.call(t, "request_revert", map[string]any{"changeId": changeID, "intent": "Wrong leads"})
	require.False(t, isError, "%v", body)
	require.Equal(t, "CHANGE", body["scope"])
	require.Equal(t, changeID, body["scopeId"])
	require.EqualValues(t, "2", body["rows"])
	id := str(t, body["revertId"])
	link := str(t, body["revertUrl"])
	require.True(t, strings.HasPrefix(link, links.DefaultLocal+"/reverts/"+id+"#2."), "no local pages: the long link: %s", link)
	msg := str(t, body["personMessage"])
	require.Contains(t, msg, "Revert of change "+changeID+": 2 rows to restore, 0 left as they are")
	require.Contains(t, msg, "Why: Wrong leads. ")
	require.True(t, strings.HasSuffix(msg, "\nReview only: this link cannot be signed. Ask the agent for a new link later.\n\n"+link), msg)
	mcptest.Require(t, msg, mcptest.LinksOf(t, body))
	require.Equal(t, []toolresult.Link{{Label: "Review and sign the revert", URL: link}}, mcptest.LinksOf(t, body))

	// The person's signature, relayed with the agent credential, reverts
	// the change.
	frag := link[strings.Index(link, "#")+1:]
	req, b, err := reverttest.ParseRequest(frag)
	require.NoError(t, err)
	as, err := env.person.Sign(approval.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	_, err = guard.ApplyRevert(context.Background(), env.a.Conn, b.RevertID, as)
	require.NoError(t, err)
	require.Equal(t, "open", leadStatus(t, env.d, 74))
}

// An agent previews and requests reverts of its own work only (RS-1, RS-6):
// another agent's change, run or task answers NOT_FOUND byte for byte as an
// unknown one does, on both tools, and nothing is prepared.
func TestRevertOfAnotherAgentsWorkIsNotFound(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	env := agentHarnessFor(t, d, d.NewAgent(t, "bot", leads, leads))
	other := d.NewAgent(t, "other", leads, leads)
	ctx := context.Background()
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), TaskID: uuid.Must(uuid.NewV7()), Text: "Other's work"}
	require.NoError(t, guard.StartRun(ctx, other.Conn, in))
	require.NoError(t, guardtest.Guarded(ctx, other.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id = 76`))
	var otherChange uuid.UUID
	require.NoError(t, other.Conn.QueryRow(ctx, `SELECT change_id FROM basalt_meta.agent_changes WHERE run_id = $1`, in.RunID).Scan(&otherChange))

	for _, tool := range []string{"preview_revert", "request_revert"} {
		for _, tc := range []struct {
			arg, reason string
			theirs      uuid.UUID
		}{
			{"changeId", "CHANGE", otherChange},
			{"runId", "RUN", in.RunID},
			{"taskId", "TASK", in.TaskID},
		} {
			call := func(id uuid.UUID) (map[string]any, string) {
				args := map[string]any{tc.arg: id.String()}
				if tool == "request_revert" {
					args["intent"] = "Undo"
				}
				body, isError := env.h.call(t, tool, args)
				steps := requireErrorSteps(t, body, isError, "NOT_FOUND", tc.reason)
				require.Equal(t, "list_runs", steps[0]["tool"])
				raw, err := json.Marshal(body)
				require.NoError(t, err)
				return body, strings.ReplaceAll(string(raw), id.String(), "<id>")
			}
			theirs, theirsText := call(tc.theirs)
			_, unknownText := call(uuid.Must(uuid.NewV7()))
			require.Equal(t, unknownText, theirsText, "%s: another agent's %s and an unknown one read alike", tool, tc.arg)
			if tc.reason == "TASK" {
				require.Contains(t, str(t, theirs["personMessage"]), "ask an agent that ran in it to request the revert")
				require.NotContains(t, str(t, theirs["personMessage"]), "basalt ")
				continue
			}
			require.Contains(t, str(t, theirs["message"]), "ask that agent", "%v", theirs)
		}
	}
	var n int
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT count(revert_id)::int FROM basalt_meta.reverts`).Scan(&n))
	require.Zero(t, n, "nothing was prepared")
	require.Equal(t, "won", leadStatus(t, d, 76))
}

// An agent requests the revert of its own lines in a task it ran in (RS-1,
// RS-7): another agent's changes in the task are left out, a row it wrote
// later is skipped, and the message points the person to widening.
func TestRequestRevertOfOwnTask(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	env := agentHarnessFor(t, d, d.NewAgent(t, "bot", leads, leads))
	other := d.NewAgent(t, "other", leads, leads)
	ctx := context.Background()
	run, isError := env.h.call(t, "run_start", map[string]any{"intent": "Win leads"})
	require.False(t, isError, "%v", run)
	taskID := str(t, run["taskId"])
	out, isError := env.h.call(t, "write", map[string]any{
		"sql": "UPDATE leads SET status = 'won' WHERE id IN (81, 83)", "intent": "They signed", "runId": run["runId"],
	})
	require.False(t, isError, "%v", out)
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), TaskID: uuid.MustParse(taskID), Text: "Same task, other agent"}
	require.NoError(t, guard.StartRun(ctx, other.Conn, in))
	require.NoError(t, guardtest.Guarded(ctx, other.Conn, in,
		`UPDATE public.leads SET status = 'lost' WHERE id = 82`, `UPDATE public.leads SET status = 'lost' WHERE id = 83`))

	preview, isError := env.h.call(t, "preview_revert", map[string]any{"taskId": taskID})
	require.False(t, isError, "%v", preview)
	require.EqualValues(t, "1", preview["rows"], "only the agent's own row 81 is restored")
	require.EqualValues(t, "1", preview["skipped"], "row 83, which the other agent wrote later, is skipped")
	items, ok := preview["items"].([]any)
	require.True(t, ok)
	require.Len(t, items, 2, "the other agent's row 82 is not in the agent's proposal")

	body, isError := env.h.call(t, "request_revert", map[string]any{"taskId": taskID, "intent": "Undo the task's lead wins"})
	require.False(t, isError, "%v", body)
	require.Equal(t, "PENDING", body["status"])
	require.Equal(t, "TASK", body["scope"])
	require.Equal(t, taskID, body["scopeId"])
	require.EqualValues(t, "1", body["rows"])
	require.EqualValues(t, "1", body["skipped"])
	requireResultSteps(t, body, "REQUESTED")
	msg := str(t, body["personMessage"])
	require.True(t, strings.HasPrefix(msg, "Revert of task "+taskID+": 1 rows to restore"), msg)
	require.Contains(t, msg, "\nYou can include other agents' changes in this task on the signing page.\n", msg)
	mcptest.Require(t, msg, mcptest.LinksOf(t, body))

	link := str(t, body["revertUrl"])
	_, b, err := reverttest.ParseRequest(link[strings.Index(link, "#")+1:])
	require.NoError(t, err)
	require.Equal(t, revert.ScopeTask, b.Select.Scope)
	require.Equal(t, []string{env.a.Role}, b.Select.Agents, "the proposal holds only the requesting agent")
	require.Equal(t, "won", leadStatus(t, d, 81), "a request reverts nothing")
}

// An own task with nothing of the agent's to undo is NOTHING_TO_REVERT
// (RS-6), and the message names the command that opens the page, where the
// person can widen to other agents' changes.
func TestRequestRevertOfOwnTaskWithNothingToRevert(t *testing.T) {
	t.Parallel()
	env := agentHarness(t)
	run, isError := env.h.call(t, "run_start", map[string]any{"intent": "Look only"})
	require.False(t, isError, "%v", run)
	read, isError := env.h.call(t, "query", map[string]any{"sql": "SELECT id FROM leads WHERE id = 84", "runId": run["runId"]})
	require.False(t, isError, "%v", read)
	taskID := str(t, run["taskId"])
	body, isError := env.h.call(t, "request_revert", map[string]any{"taskId": taskID, "intent": "Undo"})
	steps := requireScopedErrorSteps(t, body, isError, "NOTHING_TO_REVERT", "READS_ONLY", "TASK")
	require.Len(t, steps, 1)
	require.Contains(t, str(t, body["personMessage"]), "you can include the others' changes on its signing page")
	require.NotContains(t, str(t, body["personMessage"]), "basalt ")
	var n int
	require.NoError(t, env.d.Admin.QueryRow(context.Background(), `SELECT count(revert_id)::int FROM basalt_meta.reverts`).Scan(&n))
	require.Zero(t, n, "the empty proposal is rolled back")
}

func TestRequestRevertNothingToRevert(t *testing.T) {
	t.Parallel()
	env := agentHarness(t)
	runID, _ := winLeads(t, env.h, "77")
	env.d.Exec(t, `UPDATE public.leads SET status = 'person' WHERE id = 77`)

	body, isError := env.h.call(t, "request_revert", map[string]any{"runId": runID, "intent": "Undo"})
	requireErrorSteps(t, body, isError, "NOTHING_TO_REVERT", "ALL_CHANGED_BY_PEOPLE")
	require.Contains(t, str(t, body["message"]), "nothing was prepared")
	require.Contains(t, str(t, body["message"]), "preview_revert")
	require.Contains(t, str(t, body["personMessage"]), "people win")

	// A run that only read has nothing to revert either.
	run, isError := env.h.call(t, "run_start", map[string]any{"intent": "Look only"})
	require.False(t, isError, "%v", run)
	read, isError := env.h.call(t, "query", map[string]any{"sql": "SELECT id FROM leads WHERE id = 77", "runId": run["runId"]})
	require.False(t, isError, "%v", read)
	body, isError = env.h.call(t, "request_revert", map[string]any{"runId": run["runId"], "intent": "Undo"})
	requireErrorSteps(t, body, isError, "NOTHING_TO_REVERT", "READS_ONLY")
	require.Contains(t, str(t, body["personMessage"]), "it only read data")
}

func TestRequestRevertArguments(t *testing.T) {
	t.Parallel()
	env := agentHarness(t)
	runID, changeID := winLeads(t, env.h, "78")
	id := uuid.Must(uuid.NewV7()).String()
	for _, args := range []map[string]any{
		{},
		{"intent": "Undo"},
		{"runId": runID},
		{"runId": runID, "intent": ""},
		{"runId": runID, "changeId": changeID, "intent": "Undo"},
		{"runId": runID, "intent": strings.Repeat("x", 501)},
		{"runId": "not-a-uuid", "intent": "Undo"},
		{"runId": runID, "intent": "Undo", "waitForSignature": 10},
		{"runId": runID, "intent": "Undo", "reissueLink": true},
		{"runId": runID, "intent": "Undo", "signature": "basalt-revert.1.abc"},
		{"waitForSignature": 10},
		{"revertId": id, "runId": runID},
		{"revertId": id, "intent": "Undo"},
		{"revertId": id, "waitForSignature": 111},
		{"revertId": id, "waitForSignature": -1},
		{"revertId": id, "signature": "basalt-revert.1.abc"},
		{"revertId": id, "signature": "basalt-revert.1.abc", "waitForSignature": 10},
		{"revertId": id, "signature": "basalt-revert.1.abc", "reissueLink": true},
		{"revertId": id, "reissueLink": true, "waitForSignature": 10},
		{"revertId": id, "approval": "basalt-revert.1.abc"},
		{"runId": runID, "intent": "Undo", "approve": true},
	} {
		body, isError := env.h.call(t, "request_revert", args)
		requireErrorSteps(t, body, isError, "INVALID_ARGUMENT", "")
	}

	// taskId is served (RS-7): a task this agent never ran in is not found.
	body, isError := env.h.call(t, "request_revert", map[string]any{"taskId": id, "intent": "Undo"})
	requireErrorSteps(t, body, isError, "NOT_FOUND", "TASK")
	body, isError = env.h.call(t, "request_revert", map[string]any{"taskId": id})
	requireErrorSteps(t, body, isError, "INVALID_ARGUMENT", "")
	require.Contains(t, str(t, body["message"]), "intent is required with changeId, runId or taskId")
	body, isError = env.h.call(t, "request_revert", map[string]any{"taskId": id, "runId": runID, "intent": "Undo"})
	requireErrorSteps(t, body, isError, "INVALID_ARGUMENT", "")
	body, isError = env.h.call(t, "request_revert", map[string]any{"revertId": id, "taskId": id})
	requireErrorSteps(t, body, isError, "INVALID_ARGUMENT", "")

	// A revert this agent did not request is not found, whatever the form.
	for _, args := range []map[string]any{
		{"revertId": id},
		{"revertId": id, "waitForSignature": 0},
		{"revertId": id, "reissueLink": true},
	} {
		body, isError = env.h.call(t, "request_revert", args)
		requireErrorSteps(t, body, isError, "NOT_FOUND", "REVERT")
	}
	require.Equal(t, "won", leadStatus(t, env.d, 78))
}

// The agent can request a revert, but only the person's passkey applies
// it: as the agent role, apply_revert refuses a forged or replayed
// assertion and writes nothing.
func TestRequestedRevertNeedsThePersonsSignature(t *testing.T) {
	t.Parallel()
	env := agentHarness(t)
	ctx := context.Background()
	runID, _ := winLeads(t, env.h, "79")
	body, isError := env.h.call(t, "request_revert", map[string]any{"runId": runID, "intent": "Undo"})
	require.False(t, isError, "%v", body)
	link := str(t, body["revertUrl"])
	req, b, err := reverttest.ParseRequest(link[strings.Index(link, "#")+1:])
	require.NoError(t, err)

	forger, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	forger.ID = env.person.ID
	forged, err := forger.Sign(approval.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	_, err = guard.ApplyRevert(ctx, env.a.Conn, b.RevertID, forged)
	requireRevertInvalid(t, err)
	require.Equal(t, "won", leadStatus(t, env.d, 79), "a forged signature writes nothing")

	as, err := env.person.Sign(approval.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	_, err = guard.ApplyRevert(ctx, env.a.Conn, b.RevertID, as)
	require.NoError(t, err)
	require.Equal(t, "open", leadStatus(t, env.d, 79))

	// A replay of the person's signature, on this revert or on a new
	// request for the same run, is refused.
	_, err = guard.ApplyRevert(ctx, env.a.Conn, b.RevertID, as)
	requireRevertInvalid(t, err)
	again, isError := env.h.call(t, "request_revert", map[string]any{"changeId": revertedChange(t, env, runID), "intent": "Undo the undo"})
	require.False(t, isError, "%v", again)
	_, err = guard.ApplyRevert(ctx, env.a.Conn, uuid.MustParse(str(t, again["revertId"])), as)
	requireRevertInvalid(t, err)
	require.Equal(t, "open", leadStatus(t, env.d, 79), "a replay writes nothing")
}

// A large revert is a plan the person signs once: the message says so and
// the agent waits once, as for a small one.
func TestRequestRevertOfALargeRun(t *testing.T) {
	t.Parallel()
	e := newBatchEnv(t)
	body, isError := e.h.call(t, "request_revert", map[string]any{"runId": e.runID.String(), "intent": "Undo the bulk update"})
	require.False(t, isError, "%v", body)
	require.Equal(t, true, body["batched"])
	require.EqualValues(t, fmt.Sprint(planRows), body["rows"])
	msg := str(t, body["personMessage"])
	require.Contains(t, msg, fmt.Sprintf("It covers %d rows: you sign once", planRows))
	// No local pages and a plan this large: the long link is over the budget,
	// so the engine hands over the hash link with the request beside it
	// (CONTRACT.md, The request file and pasted blocks).
	link := str(t, body["revertUrl"])
	require.Regexp(t, `^`+regexp.QuoteMeta(links.DefaultLocal)+`/reverts/[0-9a-f-]{36}#h=[A-Za-z0-9_-]{22}$`, link)
	rf, ok := body["requestFile"].(map[string]any)
	require.True(t, ok, "%v", body)
	text := str(t, rf["text"])
	require.Greater(t, len(links.DefaultLocal+"/reverts/")+36+1+len(text), links.DefaultBudget, "the long link was over the budget")
	require.True(t, strings.HasSuffix(link, "#h="+links.RequestHash(text)), link)
	require.True(t, strings.HasPrefix(msg, "Revert of run "), msg)
	require.True(t, strings.HasSuffix(msg, "\n\n"+link), "the link comes last, on its own line")
	steps, ok := body["nextSteps"].([]any)
	require.True(t, ok)
	first, ok := steps[0].(map[string]any)
	require.True(t, ok)
	require.Equal(t, toolresult.ActionSendRequest, first["action"], "the agent sends the request first")
	mcptest.Require(t, msg, mcptest.LinksOf(t, body))
	require.Equal(t, []toolresult.Link{{Label: "Review and sign the revert", URL: link}}, mcptest.LinksOf(t, body))
	requireResultSteps(t, body, "REQUESTED")
}

// revertedChange is the change record of the revert of runID's change,
// which the agent may revert in turn (a revert's change shown to it).
func revertedChange(t *testing.T, env agentEnv, runID string) string {
	t.Helper()
	var id string
	require.NoError(t, env.a.Conn.QueryRow(context.Background(),
		`SELECT unnest(reverted_by)::text FROM basalt_meta.agent_changes WHERE run_id = $1`, runID).Scan(&id))
	return id
}

func requireRevertInvalid(t *testing.T, err error) {
	t.Helper()
	code, ok := guard.CodeOf(err)
	require.True(t, ok, "%v", err)
	require.Equal(t, guardmodel.CodeRevertInvalid, code, "%v", err)
}
