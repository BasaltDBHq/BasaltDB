package agent_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/revert"
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
	require.Contains(t, str(t, body["nextStep"]), "end your turn")
	link := str(t, body["revertUrl"])
	secret := links.SecretOf(link)
	require.Len(t, secret, 22, "a 128-bit secret")
	require.Equal(t, pageOrigin+"/reverts/"+id+"#s="+secret, link)
	msg := str(t, body["personMessage"])
	require.True(t, strings.HasPrefix(msg, "Revert of run "+runID+" ready for your review: 2 rows to restore, 1 left as they are "+
		"(changed after the agent). Why: Undo yesterday's lead status merge. Review and sign with your passkey: "+link+". Expires "), msg)
	require.True(t, strings.HasSuffix(msg, " UTC."), msg)
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
	as, err := env.person.Sign(revert.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	signed, err := json.Marshal(revert.NewResponse(b.RevertID, as))
	require.NoError(t, err)
	var out guard.AppliedRevert
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
	require.True(t, strings.HasPrefix(link, links.DefaultLocal+"/reverts/"+id+"#1."), "no local pages: the long link: %s", link)
	msg := str(t, body["personMessage"])
	require.Contains(t, msg, "Revert of change "+changeID+" ready for your review: 2 rows to restore, 0 left as they are")
	require.Contains(t, msg, "Why: Wrong leads. ")
	require.Contains(t, msg, link+" (the page then shows a code; apply it with: basalt revert --agent bot --config /etc/basalt-test/engine.json --apply <code>)")

	// The person's code, applied by basalt revert --apply on the agent
	// credential, reverts the change.
	frag := link[strings.Index(link, "#")+1:]
	req, b, err := revert.ParseRequest(frag)
	require.NoError(t, err)
	as, err := env.person.Sign(revert.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	_, err = guard.ApplyRevert(context.Background(), env.a.Conn, b.RevertID, as)
	require.NoError(t, err)
	require.Equal(t, "open", leadStatus(t, env.d, 74))
}

// An agent requests reverts of its own work only (N12-R7).
func TestRequestRevertOfAnotherAgentsWorkIsNotFound(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	env := agentHarnessFor(t, d, d.NewAgent(t, "bot", leads, leads))
	other := d.NewAgent(t, "other", leads, leads)
	ctx := context.Background()
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Other's work"}
	require.NoError(t, guard.StartRun(ctx, other.Conn, in))
	require.NoError(t, guardtest.Guarded(ctx, other.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id = 76`))
	var otherChange string
	require.NoError(t, other.Conn.QueryRow(ctx, `SELECT change_id::text FROM basalt_meta.agent_changes WHERE run_id = $1`, in.RunID).Scan(&otherChange))

	for _, args := range []map[string]any{
		{"runId": in.RunID.String(), "intent": "Undo"},
		{"changeId": otherChange, "intent": "Undo"},
		{"runId": uuid.Must(uuid.NewV7()).String(), "intent": "Undo"},
		{"changeId": uuid.Must(uuid.NewV7()).String(), "intent": "Undo"},
	} {
		body, isError := env.h.call(t, "request_revert", args)
		requireToolError(t, body, isError, "NOT_FOUND", "", "")
		require.Contains(t, str(t, body["message"]), "ask that agent", "%v", body)
	}
	var n int
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT count(revert_id)::int FROM basalt_meta.reverts`).Scan(&n))
	require.Zero(t, n, "nothing was prepared")
	require.Equal(t, "won", leadStatus(t, d, 76))
}

func TestRequestRevertNothingToRevert(t *testing.T) {
	t.Parallel()
	env := agentHarness(t)
	runID, _ := winLeads(t, env.h, "77")
	env.d.Exec(t, `UPDATE public.leads SET status = 'person' WHERE id = 77`)

	body, isError := env.h.call(t, "request_revert", map[string]any{"runId": runID, "intent": "Undo"})
	requireToolError(t, body, isError, "NOTHING_TO_REVERT", "", "")
	require.Contains(t, str(t, body["message"]), "nothing was prepared")
	require.Contains(t, str(t, body["message"]), "preview_revert")
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
		{"runId": runID, "intent": "Undo", "approve": true},
	} {
		body, isError := env.h.call(t, "request_revert", args)
		requireToolError(t, body, isError, "INVALID_ARGUMENT", "", "")
	}

	body, isError := env.h.call(t, "request_revert", map[string]any{"taskId": id, "intent": "Undo"})
	requireToolError(t, body, isError, "INVALID_ARGUMENT", "", "")
	require.Contains(t, str(t, body["message"]), "a whole task is reverted only by the person (basalt revert --task)")

	// The wait form is not served yet: it says so, for a revert of this
	// agent's, and changes nothing.
	body, isError = env.h.call(t, "request_revert", map[string]any{"revertId": id})
	requireToolError(t, body, isError, "NOT_FOUND", "", "")
	req, isError := env.h.call(t, "request_revert", map[string]any{"runId": runID, "intent": "Undo"})
	require.False(t, isError, "%v", req)
	body, isError = env.h.call(t, "request_revert", map[string]any{"revertId": str(t, req["revertId"]), "waitForSignature": 0})
	requireToolError(t, body, isError, "INVALID_ARGUMENT", "", "")
	require.Contains(t, str(t, body["message"]), "cannot wait for a revert's signature")
	require.Contains(t, str(t, body["message"]), "basalt revert --agent bot --config /etc/basalt-test/engine.json --apply <code>")
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
	req, b, err := revert.ParseRequest(link[strings.Index(link, "#")+1:])
	require.NoError(t, err)

	forger, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	forger.ID = env.person.ID
	forged, err := forger.Sign(revert.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	_, err = guard.ApplyRevert(ctx, env.a.Conn, b.RevertID, forged)
	requireRevertInvalid(t, err)
	require.Equal(t, "won", leadStatus(t, env.d, 79), "a forged signature writes nothing")

	as, err := env.person.Sign(revert.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
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
// nextStep points the agent at the batch loop.
func TestRequestRevertOfALargeRun(t *testing.T) {
	t.Parallel()
	e := newBatchEnv(t)
	body, isError := e.h.call(t, "request_revert", map[string]any{"runId": e.runID.String(), "intent": "Undo the bulk update"})
	require.False(t, isError, "%v", body)
	require.Equal(t, true, body["batched"])
	require.EqualValues(t, fmt.Sprint(planRows), body["rows"])
	require.Contains(t, str(t, body["personMessage"]), fmt.Sprintf("It covers %d rows: you sign it once", planRows))
	require.Contains(t, str(t, body["nextStep"]), "revert_plan with revertId, pending true and limit 200")
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
	require.Equal(t, guard.CodeRevertInvalid, code, "%v", err)
}
