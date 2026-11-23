package agent_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp/mcptest"
	"github.com/basaltdbhq/basaltdb/internal/core/links/linkstest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// listPending calls list_pending and returns its items.
func listPending(t *testing.T, h harness, args map[string]any) (map[string]any, []map[string]any) {
	t.Helper()
	body, isError := h.call(t, "list_pending", args)
	require.False(t, isError, "%v", body)
	return body, items(t, body)
}

// One list (LP-1): a held write and a revert of the agent, newest first,
// one cursor across both kinds, and the filters by kind, status and run.
// The revert's request and its reissue each notify the person (LP-2).
func TestListPendingListsRevertsWithHeldWrites(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	env := agentHarnessFor(t, d, d.NewAgent(t, "bot", leads, leads), pageOrigin)
	args := holdWrite(t, env.h, nil)
	body, isError := env.h.call(t, "write", args)
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
	approvalID := str(t, approvalOf(t, body)["approvalId"])
	run, _ := winLeads(t, env.h, "50, 51")
	req := requestRevert(t, env.h, map[string]any{"runId": run, "intent": "Undo the win"})
	revertID := str(t, req["revertId"])

	sent := env.sent.revertNotices()
	require.Len(t, sent, 1, "request_revert notifies the person")
	require.Equal(t, revertID, sent[0].RevertID.String())
	require.Equal(t, "Revert of run "+run+": 2 rows to restore, 0 left as they are (changed after the agent).", sent[0].Headline)
	require.Equal(t, "Undo the win", sent[0].Intent)
	require.Contains(t, sent[0].RevertURL, "#2.", "the notice gets the long link")
	require.False(t, sent[0].Widened)

	_, list := listPending(t, env.h, map[string]any{})
	require.Len(t, list, 2)
	require.Equal(t, "REVERT", list[0]["kind"], "newest first")
	require.Equal(t, "APPROVAL", list[1]["kind"])
	require.Equal(t, approvalID, list[1]["approvalId"])
	rv := list[0]
	require.Equal(t, revertID, rv["revertId"])
	require.Equal(t, "PENDING", rv["status"])
	require.Equal(t, "RUN", rv["scope"])
	require.Equal(t, run, rv["scopeId"])
	require.Equal(t, false, rv["widened"])
	require.Equal(t, sent[0].Headline, rv["headline"])
	require.Contains(t, str(t, rv["revertUrl"]), "#2.", "listing touches no link: the long link")
	require.NotContains(t, str(t, rv["personMessage"]), "http", "the message points back to the link already given")
	mcptest.Require(t, str(t, rv["personMessage"]), mcptest.LinksOf(t, rv))
	requirePendingSteps(t, rv, "REVERT_PENDING")

	// One cursor across both kinds.
	page, first := listPending(t, env.h, map[string]any{"limit": 1})
	require.Len(t, first, 1)
	require.Equal(t, "REVERT", first[0]["kind"])
	page, second := listPending(t, env.h, map[string]any{"limit": 1, "cursor": str(t, page["nextCursor"])})
	require.Len(t, second, 1)
	require.Equal(t, "APPROVAL", second[0]["kind"])
	require.NotContains(t, page, "nextCursor")
	_, oldest := listPending(t, env.h, map[string]any{"sort": "id"})
	require.Equal(t, "APPROVAL", oldest[0]["kind"], "oldest first")

	for name, filter := range map[string]map[string]any{
		"kind REVERT":     {"kind": "REVERT"},
		"status APPLYING": {"status": "APPLYING"},
	} {
		_, got := listPending(t, env.h, filter)
		for _, it := range got {
			require.Equal(t, "REVERT", it["kind"], name)
		}
	}
	for name, filter := range map[string]map[string]any{
		"kind APPROVAL":   {"kind": "APPROVAL"},
		"status APPROVED": {"status": "APPROVED"},
		"a run":           {"runId": str(t, args["runId"])},
	} {
		_, got := listPending(t, env.h, filter)
		for _, it := range got {
			require.Equal(t, "APPROVAL", it["kind"], name)
		}
	}

	// A reissue gives the revert a new short link and notifies again.
	_, reissued := listPending(t, env.h, map[string]any{"kind": "REVERT", "reissueLink": true})
	require.Len(t, reissued, 1)
	short := str(t, reissued[0]["revertUrl"])
	require.Equal(t, pageOrigin+"/reverts/"+revertID+"#s="+linkstest.SecretOf(short), short)
	require.Contains(t, str(t, reissued[0]["personMessage"]), short)
	sent = env.sent.revertNotices()
	require.Len(t, sent, 2, "the reissue notifies the person")
	require.Equal(t, short, sent[1].ShortURL)
	request := requestRevert(t, env.h, map[string]any{"revertId": revertID, "reissueLink": true})
	require.NotEmpty(t, request["revertUrl"])
	require.Len(t, env.sent.revertNotices(), 3, "request_revert's reissue notifies too")
}

// requirePendingSteps checks a list_pending item's steps against its
// catalog case.
func requirePendingSteps(t *testing.T, item map[string]any, kase string) []map[string]any {
	t.Helper()
	c, err := mcpcontract.LoadNextSteps()
	require.NoError(t, err)
	for _, r := range c.Results {
		if r.Tool == "list_pending" && r.Case == kase {
			return requireSteps(t, item, r.Steps, r.PersonMessage)
		}
	}
	require.Failf(t, "no catalog case", "list_pending %s", kase)
	return nil
}

// A signed large plan is listed APPLYING, for the agent's batch loop.
func TestListPendingListsASignedPlan(t *testing.T) {
	t.Parallel()
	e := newBatchEnv(t)
	e.sign(t)
	_, list := listPending(t, e.h, map[string]any{"kind": "REVERT"})
	require.Len(t, list, 1)
	it := list[0]
	require.Equal(t, "APPLYING", it["status"])
	require.Equal(t, true, it["batched"])
	require.NotContains(t, it, "revertUrl")
	require.Contains(t, it, "progress")
	require.Contains(t, it, "applyBy")
	steps := requirePendingSteps(t, it, "REVERT_APPLYING")
	require.Equal(t, "revert_plan", steps[0]["tool"])
}

// A widened revert is listed with status and totals only: no scope, link
// or scope in its headline or message (RS-5, LP-3). A reissue resets it to
// the agent's proposal, with a link for that, and the person's link then
// reads LINK_RESET.
func TestListPendingShowsAWidenedRevertWithoutItsScope(t *testing.T) {
	t.Parallel()
	e := newRescopeEnv(t)
	id, agentSecret := e.request(t)
	personSecret := newLinkSecret(t)
	var wide scopeAnswer
	require.Equal(t, http.StatusOK, e.p.post(scopePath(id), pageOrigin, agentSecret,
		e.widenBody(t, e.person, id, e.nonce(t, id, agentSecret), e.every(), personSecret), &wide))

	_, list := listPending(t, e.h, map[string]any{"kind": "REVERT"})
	require.Len(t, list, 1)
	it := list[0]
	require.Equal(t, true, it["widened"])
	for _, key := range []string{"scope", "scopeId", "revertUrl", "links"} {
		require.NotContains(t, it, key)
	}
	require.Equal(t, "Revert widened by the person: 2 rows to restore.", it["headline"])
	require.NotContains(t, str(t, it["personMessage"]), e.task.String())
	steps := requirePendingSteps(t, it, "REVERT_PENDING")
	require.NotContains(t, steps[0], "url", "the agent has no link to the person's scope")

	_, list = listPending(t, e.h, map[string]any{"kind": "REVERT", "reissueLink": true})
	it = list[0]
	require.Equal(t, false, it["widened"], "reset to the agent's proposal")
	require.Equal(t, e.task.String(), it["scopeId"])
	require.NotEmpty(t, it["revertUrl"])
	var perr pageError
	require.Equal(t, http.StatusNotFound, e.p.get(revertPath(id), personSecret, &perr))
	require.Equal(t, "LINK_RESET", perr.Reason)
	sent := e.sent.revertNotices()
	require.NotEmpty(t, sent)
	require.False(t, sent[len(sent)-1].Widened, "the notice is for the proposal the reset left")
	var reverts int
	require.NoError(t, e.d.Admin.QueryRow(context.Background(), `SELECT count(revert_id)::int FROM basalt_meta.reverts`).Scan(&reverts))
	require.Equal(t, 1, reverts)
}
