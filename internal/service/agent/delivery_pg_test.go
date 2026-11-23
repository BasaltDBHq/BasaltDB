package agent_test

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/links/linkstest"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
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
	agent.SetDeliverer(env.svc, rec)
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
		require.Regexp(t, noticeLinkPattern(t), link, "a link the engine issued fits the notice's schema")
		require.Equal(t, agent.NoticeApprovalRequested, got[0].Kind)
		require.Equal(t, id, got[0].ApprovalID.String())
		require.Equal(t, "Update 15 rows in public·leads", got[0].Headline)
		require.Equal(t, str(t, ap["expiresAt"]), got[0].ExpiresAt.UTC().Format(time.RFC3339))

		var req approval.Request
		require.Equal(t, http.StatusOK, p.get("/api/v1/approvals/"+id, linkstest.SecretOf(link), &req),
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
		require.Regexp(t, noticeLinkPattern(t), link)
	})
}

// noticeLinkPattern is the pattern of a notice's link in
// deliver.schema.json: a link the engine hands an agent must fit it, or the
// engine would leave it out of the notice.
func noticeLinkPattern(t *testing.T) *regexp.Regexp {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "api", "plugin", "protocol", "deliver.schema.json"))
	require.NoError(t, err)
	var doc struct {
		Defs struct {
			Notice struct {
				Properties struct {
					Link struct {
						Pattern string `json:"pattern"`
					} `json:"link"`
				} `json:"properties"`
			} `json:"notice"`
		} `json:"$defs"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	require.NotEmpty(t, doc.Defs.Notice.Properties.Link.Pattern)
	return regexp.MustCompile(doc.Defs.Notice.Properties.Link.Pattern)
}

// panics is a deliverer that fails in the worst way.
type panics struct{}

func (panics) DeliverLink(agent.LinkNotice) { panic("the deliverer broke") }

// TestDelivererCannotChangeTheAnswer: with a deliverer that panics, the
// agent gets the answer it gets with none: held, with its link.
func TestDelivererCannotChangeTheAnswer(t *testing.T) {
	t.Parallel()
	env, _ := deliveryHarness(t, true)
	agent.SetDeliverer(env.svc, panics{})
	body, isError := env.h.call(t, "write", holdWrite(t, env.h, nil))
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
	require.Contains(t, str(t, approvalOf(t, body)["approvalUrl"]), "#s=")
	pending, isError := env.h.call(t, "list_pending", map[string]any{"reissueLink": true})
	require.False(t, isError, "%v", pending)
	require.Len(t, items(t, pending), 1)
}

// TestWaitingWriteIsNoticedWhenHeld: a new write that waits for the person
// is noticed when it is held, while its call is still open, with the link
// the call's answer then carries. The answer sends no second notice, and a
// wait that ran out on a repeat restates the link and sends nothing.
func TestWaitingWriteIsNoticedWhenHeld(t *testing.T) {
	t.Parallel()
	env, rec := deliveryHarness(t, true)
	wait := 2
	args := holdWrite(t, env.h, &wait)
	done := make(chan map[string]any, 1)
	go func() {
		body, _ := env.h.call(t, "write", args)
		done <- body
	}()
	env.waitPolling(t)
	held := rec.all()
	require.Len(t, held, 1, "held and waiting: the person is told now, not when the call answers")
	require.Empty(t, done, "the call is still open")
	require.Equal(t, agent.NoticeApprovalRequested, held[0].Kind)
	require.Contains(t, held[0].Link, "#s=")

	body := <-done
	requireToolError(t, body, true, "APPROVAL_REQUIRED", "", "")
	ap := approvalOf(t, body)
	require.Equal(t, held[0].Link, str(t, ap["approvalUrl"]), "the answer carries the noticed link, byte for byte")
	require.Equal(t, held[0].ApprovalID.String(), str(t, ap["approvalId"]))
	require.Len(t, rec.take(), 1, "the answer sends no second notice")

	args["approvalId"] = str(t, ap["approvalId"])
	body, isError := env.h.call(t, "write", args)
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
	require.Empty(t, rec.all(), "a wait that ran out restates the link")
}

// TestWaitingWriteSignedFromItsNotice: the person signs through the link of
// the notice while the agent's first call still waits. The call answers
// success, and nothing else is noticed.
func TestWaitingWriteSignedFromItsNotice(t *testing.T) {
	t.Parallel()
	env, rec := deliveryHarness(t, true)
	p := newLocalPages(t, env)
	wait := 60
	args := holdWrite(t, env.h, &wait)
	type answer struct {
		body    map[string]any
		isError bool
	}
	done := make(chan answer, 1)
	start := time.Now()
	go func() {
		b, e := env.h.call(t, "write", args)
		done <- answer{b, e}
	}()
	env.waitPolling(t)
	held := rec.all()
	require.Len(t, held, 1, "noticed while the call is open")
	require.Empty(t, done, "the call is still open")

	id, secret := held[0].ApprovalID.String(), linkstest.SecretOf(held[0].Link)
	require.Equal(t, http.StatusOK, p.post("/api/v1/approvals/"+id+"/approve", pageOrigin, secret, p.signApproval(id, secret, env.person), nil),
		"the notice's link is the held write's own")
	got := <-done
	require.False(t, got.isError, "%v", got.body)
	require.Equal(t, "APPLIED", got.body["status"])
	require.Less(t, time.Since(start), 30*time.Second, "applied as soon as it was signed")
	require.Len(t, rec.all(), 1, "one notice for the held write, none when its call answers")
}

// TestNoticeWithoutStandaloneLinkHasNone: when the agent's answer hands
// over a hash link, whose request travels beside it, the notice has no
// link.
func TestNoticeWithoutStandaloneLinkHasNone(t *testing.T) {
	t.Parallel()
	env, rec := deliveryHarness(t, false)
	agent.SetLinkBudget(env.svc, 200)
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
	require.Regexp(t, noticeLinkPattern(t), got[0].Link)
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

		// The CLI's link route is gone: nothing issues a link but the
		// agent's own tools.
		id := str(t, req["revertId"])
		require.Equal(t, http.StatusNotFound, p.post("/api/v1/reverts/"+id+"/links", pageOrigin, "", []byte(`{"proof":"x"}`), nil))
		require.Empty(t, rec.all())

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

func TestNoticeHeadline(t *testing.T) {
	t.Parallel()
	require.Equal(t, "Update 27 rows in public·leads", agent.NoticeHeadline("Update 27 rows in public.leads"))
	require.Equal(t, "Delete 1 row in public·customers + 30 cascaded rows (public·invoices 28, public·payments 2 [values hidden])",
		agent.NoticeHeadline("Delete 1 row in public.customers + 30 cascaded rows (public.invoices 28, public.payments 2 [values hidden])"))
	const revert = "Revert of run 0193a1b2-7c4d-7e8f-9a0b-1c2d3e4f5a6b: 27 rows to restore, 0 left as they are (changed after the agent)."
	require.Equal(t, revert, agent.NoticeHeadline(revert))
	require.Equal(t, "Update 1 row in evil·example·com/x", agent.NoticeHeadline("Update 1 row in evil.example.com/x\n\u202e"))
	long := agent.NoticeHeadline("Update 1 row in " + strings.Repeat("a", 2000))
	require.Len(t, []rune(long), 1000)
	require.True(t, strings.HasSuffix(long, "…"))
}
