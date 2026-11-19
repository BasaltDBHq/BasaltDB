package agent_test

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
)

// delivered records the notices the agent's service hands its deliverer,
// the seam the approval.deliver plugins sit behind.
type delivered struct {
	mu   sync.Mutex
	list []agent.LinkNotice
}

func (d *delivered) DeliverLink(n agent.LinkNotice) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.list = append(d.list, n)
}

func (d *delivered) all() []agent.LinkNotice {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]agent.LinkNotice(nil), d.list...)
}

// take returns the notices since the last take.
func (d *delivered) take() []agent.LinkNotice {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := d.list
	d.list = nil
	return out
}

// deliveryHarness is an agent "bot" whose notices are recorded; with pages
// the engine serves its local pages and hands short links over.
func deliveryHarness(t *testing.T, pages bool) (agentEnv, *delivered) {
	t.Helper()
	d := guardtest.New(t).WithDemo(t)
	var origin []string
	if pages {
		origin = []string{pageOrigin}
	}
	env := agentHarnessFor(t, d, d.NewAgent(t, "bot", leads, leads), origin...)
	rec := &delivered{}
	env.svc.Deliverer = rec
	return env, rec
}

// TestNoticeCarriesTheAgentsLink: the notice of a held write carries the
// link of the agent's own answer, byte for byte, short or long, and making
// it issued and revoked nothing: the agent's link still opens the page.
func TestNoticeCarriesTheAgentsLink(t *testing.T) {
	t.Parallel()
	t.Run("short link", func(t *testing.T) {
		t.Parallel()
		env, rec := deliveryHarness(t, true)
		p := newLocalPages(t, env)
		body, isError := env.h.call(t, "write", holdWrite(t, env.h, nil))
		requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
		ap := approvalOf(t, body)
		link, id := str(t, ap["approvalUrl"]), str(t, ap["approvalId"])
		require.Contains(t, link, "#s=")

		got := rec.all()
		require.Len(t, got, 1)
		require.Equal(t, link, got[0].Link, "the answer's link, byte for byte")
		require.Equal(t, agent.NoticeApprovalRequested, got[0].Kind)
		require.Equal(t, id, got[0].ApprovalID.String())
		require.Equal(t, "Update 15 rows in public·leads", got[0].Headline)
		require.Equal(t, str(t, ap["expiresAt"]), got[0].ExpiresAt.UTC().Format(time.RFC3339))

		var req approval.Request
		require.Equal(t, http.StatusOK, p.get("/api/v1/approvals/"+id, links.SecretOf(link), &req),
			"the agent's link still works: the notice issued no link of its own")
	})
	t.Run("long link", func(t *testing.T) {
		t.Parallel()
		env, rec := deliveryHarness(t, false)
		body, isError := env.h.call(t, "write", holdWrite(t, env.h, nil))
		requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
		link := str(t, approvalOf(t, body)["approvalUrl"])
		require.Contains(t, link, "#2.")
		got := rec.all()
		require.Len(t, got, 1)
		require.Equal(t, link, got[0].Link)
	})
}

// TestNoticeWaitsForTheAgentsAnswer: a new write that waits for the
// person is noticed only when its answer hands the link over, never while
// the agent has no link yet; a wait that ran out on a repeat restates the
// link and sends nothing.
func TestNoticeWaitsForTheAgentsAnswer(t *testing.T) {
	t.Parallel()
	env, rec := deliveryHarness(t, true)
	wait := 1
	args := holdWrite(t, env.h, &wait)
	done := make(chan map[string]any, 1)
	go func() {
		body, _ := env.h.call(t, "write", args)
		done <- body
	}()
	env.waitPolling(t)
	require.Empty(t, rec.all(), "held and waiting: the agent has no link yet, so nobody else has")
	body := <-done
	ap := approvalOf(t, body)
	got := rec.take()
	require.Len(t, got, 1)
	require.Equal(t, str(t, ap["approvalUrl"]), got[0].Link)

	args["approvalId"] = str(t, ap["approvalId"])
	body, isError := env.h.call(t, "write", args)
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
	require.Empty(t, rec.all(), "a wait that ran out restates the link")
}

// TestNoticeWithoutStandaloneLinkHasNone: when the agent's answer hands
// over a hash link, whose request travels beside it, the notice has no
// link.
func TestNoticeWithoutStandaloneLinkHasNone(t *testing.T) {
	t.Parallel()
	env, rec := deliveryHarness(t, false)
	env.svc.LinkBudget = 200
	body, isError := env.h.call(t, "write", holdWrite(t, env.h, nil))
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
	ap := approvalOf(t, body)
	require.Contains(t, str(t, ap["approvalUrl"]), "#h=")
	got := rec.all()
	require.Len(t, got, 1)
	require.Empty(t, got[0].Link)
	require.Equal(t, str(t, ap["approvalId"]), got[0].ApprovalID.String())
}

// TestRevertAndReissueAreNoticed: a prepared revert and every link the
// agent asks for again are noticed, each with the link of that answer.
func TestRevertAndReissueAreNoticed(t *testing.T) {
	t.Parallel()
	env, rec := deliveryHarness(t, true)
	runID, _ := winLeads(t, env.h, "46, 47")
	require.Empty(t, rec.all(), "an applied write is no notice")

	req := requestRevert(t, env.h, map[string]any{"runId": runID, "intent": "Undo"})
	revertID := str(t, req["revertId"])
	got := rec.take()
	require.Len(t, got, 1)
	require.Equal(t, agent.NoticeRevertRequested, got[0].Kind)
	require.Equal(t, revertID, got[0].RevertID.String())
	require.Equal(t, str(t, req["revertUrl"]), got[0].Link)
	require.Contains(t, got[0].Link, "#s=")
	require.Equal(t, "Revert of run "+runID+": 2 rows to restore, 0 left as they are (changed after the agent).", got[0].Headline)
	require.Equal(t, str(t, req["expiresAt"]), got[0].ExpiresAt.UTC().Format(time.RFC3339))

	again := requestRevert(t, env.h, map[string]any{"revertId": revertID, "reissueLink": true})
	got = rec.take()
	require.Len(t, got, 1)
	require.Equal(t, agent.NoticeLinkReplaced, got[0].Kind)
	require.Equal(t, str(t, again["revertUrl"]), got[0].Link)
	require.NotEqual(t, str(t, req["revertUrl"]), got[0].Link)

	// A held write beside it: list_pending with reissueLink notices each
	// item it issued a link for.
	body, isError := env.h.call(t, "write", holdWrite(t, env.h, nil))
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
	approvalID := str(t, approvalOf(t, body)["approvalId"])
	rec.take()
	pending, isError := env.h.call(t, "list_pending", map[string]any{"reissueLink": true})
	require.False(t, isError, "%v", pending)
	list := items(t, pending)
	require.Len(t, list, 2)
	got = rec.take()
	require.Len(t, got, 2)
	for _, n := range got {
		require.Equal(t, agent.NoticeLinkReplaced, n.Kind)
		for _, item := range list {
			switch {
			case item["approvalId"] == approvalID && n.ApprovalID.String() == approvalID:
				require.Equal(t, str(t, item["approvalUrl"]), n.Link)
				require.Equal(t, "Update 15 rows in public·leads", n.Headline)
			case item["revertId"] == revertID && n.RevertID.String() == revertID:
				require.Equal(t, str(t, item["revertUrl"]), n.Link)
			}
		}
		require.NotEmpty(t, n.Link)
	}
	require.NotEqual(t, got[0].ApprovalID, got[1].ApprovalID, "one notice per item")
}

// TestCommandLineReissueSendsNoNotice: nothing but the three moments makes
// a notice. A link issued for the person's own command line, a list that
// issues no link, and a reissue that issued none (an engine with no pages
// restates the long link) send nothing.
func TestCommandLineReissueSendsNoNotice(t *testing.T) {
	t.Parallel()
	t.Run("the person's command line", func(t *testing.T) {
		t.Parallel()
		env, rec := deliveryHarness(t, true)
		p := newLocalPages(t, env)
		runID, _ := winLeads(t, env.h, "46, 47")
		req := requestRevert(t, env.h, map[string]any{"runId": runID, "intent": "Undo"})
		body, isError := env.h.call(t, "write", holdWrite(t, env.h, nil))
		requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
		rec.take()

		// basalt revert / basalt approve --show ask the pages for a link
		// with proof of the binding text.
		id := str(t, req["revertId"])
		_, binding := longLinkBindingOfRevert(t, env, id)
		var out struct{ URL string }
		require.Equal(t, http.StatusOK, p.post("/api/v1/reverts/"+id+"/links", "", "", []byte(`{"proof":"`+links.IssueProof(binding)+`"}`), &out))
		require.True(t, strings.HasPrefix(out.URL, pageOrigin+"/reverts/"+id+"#s="), out.URL)
		require.Empty(t, rec.all(), "that link is in the person's hands already")

		pending, isError := env.h.call(t, "list_pending", map[string]any{})
		require.False(t, isError, "%v", pending)
		require.Len(t, items(t, pending), 2)
		require.Empty(t, rec.all(), "a list that issues no link")
	})
	t.Run("no link issued", func(t *testing.T) {
		t.Parallel()
		env, rec := deliveryHarness(t, false)
		body, isError := env.h.call(t, "write", holdWrite(t, env.h, nil))
		requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
		rec.take()
		pending, isError := env.h.call(t, "list_pending", map[string]any{"reissueLink": true})
		require.False(t, isError, "%v", pending)
		require.Len(t, items(t, pending), 1)
		require.Empty(t, rec.all(), "no new link was issued: the first one still works")
	})
}

// longLinkBindingOfRevert is revert id's binding text, read as the agent
// reads it.
func longLinkBindingOfRevert(t *testing.T, env agentEnv, id string) (string, string) {
	t.Helper()
	r, err := env.svc.Store.FindRevert(t.Context(), uuid.MustParse(id))
	require.NoError(t, err)
	binding := r.BindingText
	return id, binding
}

func TestNoticeHeadline(t *testing.T) {
	t.Parallel()
	require.Equal(t, "Update 27 rows in public·leads", agent.NoticeHeadline("Update 27 rows in public.leads"))
	require.Equal(t, "Delete 1 row in public·customers + 30 cascaded rows (public·invoices 28, public·payments 2 [values hidden])",
		agent.NoticeHeadline("Delete 1 row in public.customers + 30 cascaded rows (public.invoices 28, public.payments 2 [values hidden])"))
	const revert = "Revert of run 0193a1b2-7c4d-7e8f-9a0b-1c2d3e4f5a6b: 27 rows to restore, 0 left as they are (changed after the agent)."
	require.Equal(t, revert, agent.NoticeHeadline(revert))
	require.Equal(t, "Update 1 row in evil·example·com/x", agent.NoticeHeadline("Update 1 row in evil.example.com/x\n‮"))
	long := agent.NoticeHeadline("Update 1 row in " + strings.Repeat("a", 2000))
	require.Len(t, []rune(long), 1000)
	require.True(t, strings.HasSuffix(long, "…"))
}
