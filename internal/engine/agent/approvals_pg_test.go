package agent_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/agentdb"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/mcp/mcptest"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
)

// notices records what the engine would send to Telegram.
type notices struct {
	mu      sync.Mutex
	sent    []agent.HeldNotice
	reverts []agent.RevertNotice
}

func (n *notices) NotifyRevert(_ context.Context, r agent.RevertNotice) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.reverts = append(n.reverts, r)
	return nil
}

// revertNotices returns what the engine sent about reverts so far.
func (n *notices) revertNotices() []agent.RevertNotice {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]agent.RevertNotice(nil), n.reverts...)
}

func (n *notices) NotifyHeld(_ context.Context, h agent.HeldNotice) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent = append(n.sent, h)
	return nil
}

// approvalHarness is a guarded demo database, an agent "bot" on leads, the
// person's registered passkey, and an engine that notifies into notices.
func approvalHarness(t *testing.T) (*guardtest.DB, harness, *passkeytest.Authenticator, *notices) {
	t.Helper()
	e := agentHarness(t)
	return e.d, e.h, e.person, e.sent
}

// agentEnv is approvalHarness's setup with the connected agent.
type agentEnv struct {
	d      *guardtest.DB
	a      *guardtest.Agent
	h      harness
	person *passkeytest.Authenticator
	sent   *notices
	svc    *agent.Service
	blind  *agent.BlindCache
	// finds counts the agent's approval reads: one when a call looks its
	// approval up, one more for every poll while it waits.
	finds *finds
	// revertFinds is the same for the revert the agent waits on.
	revertFinds *revertFinds
}

// finds wraps the approval store and counts FindApproval calls, so a test
// can tell that the agent is waiting without guessing a delay.
type finds struct {
	agent.ApprovalStore
	n atomic.Int64
}

func (f *finds) FindApproval(ctx context.Context, id uuid.UUID) (ledger.Approval, error) {
	f.n.Add(1)
	return f.ApprovalStore.FindApproval(ctx, id)
}

// revertFinds wraps the revert store and counts FindRevert calls.
type revertFinds struct {
	agent.RevertStore
	n atomic.Int64
}

func (f *revertFinds) FindRevert(ctx context.Context, id uuid.UUID) (ledger.Revert, error) {
	f.n.Add(1)
	return f.RevertStore.FindRevert(ctx, id)
}

// pollUntil reports whether cond became true within d, checking often. It
// does not fail the test, so goroutines can use it.
func pollUntil(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// afterRevertPolls returns a function that blocks until the agent, from
// now on, has looked its revert up and polled once for the signature: it is
// in its wait. The baseline is read now, so call this before starting the
// agent's call, and run the returned function in the goroutine that signs.
func (e agentEnv) afterRevertPolls() func() {
	base := e.revertFinds.n.Load()
	return func() {
		pollUntil(10*time.Second, func() bool { return e.revertFinds.n.Load() >= base+2 })
	}
}

// waitPolling blocks until the agent has polled for the signature at least
// once, which means it is in its wait.
func (e agentEnv) waitPolling(t *testing.T) {
	t.Helper()
	require.Eventually(t, func() bool { return e.finds.n.Load() >= 2 }, 10*time.Second, 5*time.Millisecond,
		"the agent never started polling for the signature")
}

func agentHarness(t *testing.T) agentEnv {
	t.Helper()
	d := guardtest.New(t).WithDemo(t)
	return agentHarnessFor(t, d, d.NewAgent(t, "bot", leads, leads))
}

// agentHarnessFor serves agent a of database d through MCP, with the
// person's passkey registered. pagesOrigin, when given, is the origin of
// the engine's local pages, for short links.
func agentHarnessFor(t *testing.T, d *guardtest.DB, a *guardtest.Agent, pagesOrigin ...string) agentEnv {
	t.Helper()
	person, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	require.NoError(t, guard.RegisterPasskey(context.Background(), d.Admin, person.Credential(), "app"))

	cmds, err := agent.NewCommands("bot", "/etc/basalt-test/engine.json", "linux", nil)
	require.NoError(t, err)
	pool, err := agentdb.NewPool(context.Background(), a.URL, 2)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	limits := sqlguard.DefaultLimits()
	store := agentdb.NewStore(pool, limits, time.Now)
	sent := &notices{}
	watched := &finds{ApprovalStore: store}
	watchedReverts := &revertFinds{RevertStore: store}
	blind := agent.NewBlindCache(func(ctx context.Context, tables []string) ([]string, error) {
		return guard.RLSBlindTables(ctx, pool, "", tables)
	})
	svc := agent.NewService(agent.Deps{
		Name: "bot", Reader: agentdb.NewReader(pool, limits, time.Now), Store: store, Reads: store, Approvals: watched,
		Reverts: watchedReverts, Notifier: sent, Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Commands: cmds, PagesOrigin: strings.Join(pagesOrigin, ""), Poll: testPoll, RLS: blind,
	})
	return agentEnv{d: d, a: a, h: harness{server: mcp.NewServer(mcp.Info{Name: "basalt"}, agent.Tools(svc)...)}, person: person, sent: sent, svc: svc, blind: blind, finds: watched, revertFinds: watchedReverts}
}

func approvalOf(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	ap, ok := body["approval"].(map[string]any)
	require.True(t, ok, "%v", body)
	return ap
}

// signLink does what the person does on the approval page: decode the
// link, check it, and sign the binding with the passkey.
func signLink(t *testing.T, link string, signer *passkeytest.Authenticator) string {
	t.Helper()
	frag := link[strings.Index(link, "#")+1:]
	req, b, err := approval.ParseRequest(frag)
	require.NoError(t, err)
	require.Empty(t, req.CredentialIDs, "a format 2 link carries no credential ids: the passkeys are discoverable")
	as, err := signer.Sign(approval.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	code, err := approval.NewResponse(b.ApprovalID, as).Code()
	require.NoError(t, err)
	return code
}

func TestHeldWriteApprovedWithPasskey(t *testing.T) {
	t.Parallel()
	d, h, person, sent := approvalHarness(t)
	run, isError := h.call(t, "run_start", map[string]any{"intent": "Close the stale leads"})
	require.False(t, isError, "%v", run)
	runID := str(t, run["runId"])
	args := map[string]any{
		"sql": "UPDATE leads SET status = $1 WHERE id BETWEEN $2 AND $3", "params": []any{"closed", 21, 35},
		"intent": "Leads 21 to 35 went cold", "runId": runID,
	}

	body, isError := h.call(t, "write", args)
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
	ap := approvalOf(t, body)
	require.Equal(t, json.Number("15"), ap["rows"])
	link := str(t, ap["approvalUrl"])
	require.True(t, strings.HasPrefix(link, links.DefaultLocal+"/approvals/"+str(t, ap["approvalId"])+"#2."), link)
	approvalID := str(t, ap["approvalId"])
	command := "basalt approve --agent bot --config /etc/basalt-test/engine.json --open " + approvalID
	require.Equal(t, command, ap["approveCommand"])
	require.Contains(t, str(t, body["message"]), "Show the person approval.personMessage verbatim")
	require.Contains(t, str(t, body["message"]), "without ending your turn, call write once with the same arguments plus approvalId")
	require.Contains(t, str(t, body["message"]), "do not wait again")
	require.Equal(t, "Update 15 rows in public.leads", ap["headline"])
	require.True(t, strings.HasPrefix(str(t, ap["personMessage"]),
		"Held for your approval: Update 15 rows in public·leads.\nApprove it with your passkey here; the page then shows a code for the agent:\n\n"+
			link+"\n\nOr run: "+command+"\nExpires "),
		"without local pages and within the budget the message carries the long link: %v", ap["personMessage"])
	mcptest.Require(t, str(t, ap["personMessage"]), mcptest.LinksOf(t, ap))
	require.Equal(t, []mcp.Link{{Label: "Approve the held write", URL: link}}, mcptest.LinksOf(t, ap))
	require.Equal(t, "open", leadStatus(t, d, 21), "a held write changes nothing")
	require.Len(t, sent.sent, 1)
	require.Equal(t, link, sent.sent[0].ApprovalURL)
	require.Equal(t, 15, sent.sent[0].Rows)
	require.Equal(t, "Update 15 rows in public.leads", sent.sent[0].Headline)

	pending, isError := h.call(t, "list_pending", map[string]any{"runId": runID})
	require.False(t, isError, "%v", pending)
	list := items(t, pending)
	require.Len(t, list, 1)
	require.Equal(t, approvalID, list[0]["approvalId"])
	require.Equal(t, "PENDING", list[0]["status"])
	require.Equal(t, link, list[0]["approvalUrl"])
	require.Equal(t, command, list[0]["approveCommand"])
	require.Equal(t, ap["personMessage"], list[0]["personMessage"], "list_pending gives the link back")
	require.Equal(t, ap["links"], list[0]["links"])
	mcptest.Require(t, str(t, list[0]["personMessage"]), mcptest.LinksOf(t, list[0]))
	require.Equal(t, ap["headline"], list[0]["headline"])
	pendingSteps := requireToolSteps(t, list[0], "list_pending", "PENDING")
	require.Equal(t, link, pendingSteps[0]["url"])
	require.Equal(t, command, pendingSteps[0]["command"])
	require.Equal(t, []any{"status"}, list[0]["assignedColumns"])

	withApproval := func(extra map[string]any) map[string]any {
		out := map[string]any{"approvalId": approvalID}
		for k, v := range args {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}

	// Without waiting, an unsigned approval is refused at once by the guard.
	body, isError = h.call(t, "write", withApproval(map[string]any{"waitForApproval": 0}))
	requireToolError(t, body, isError, "APPROVAL_INVALID", "", "")
	require.Contains(t, body["message"], "not approved yet")

	// A wait that runs out tells the agent to end its turn, not to wait again.
	body, isError = h.call(t, "write", withApproval(map[string]any{"waitForApproval": 1}))
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
	require.Contains(t, str(t, body["message"]), "Do not call write to wait again. End your turn")
	require.Contains(t, str(t, body["message"]), "apply it when they tell you they approved")
	require.Equal(t, approvalID, approvalOf(t, body)["approvalId"])
	require.Equal(t, "open", leadStatus(t, d, 21), "nothing applied")

	forger, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	forger.ID = person.ID
	body, isError = h.call(t, "write", withApproval(map[string]any{"approval": signLink(t, link, forger)}))
	requireToolError(t, body, isError, "APPROVAL_INVALID", "", "BS005")
	require.Contains(t, body["message"], "bad passkey signature")

	body, isError = h.call(t, "write", withApproval(map[string]any{"params": []any{"closed", 21, 36}}))
	requireToolError(t, body, isError, "APPROVAL_INVALID", "", "")
	require.Contains(t, body["message"], "exactly those of the held write")

	code := signLink(t, link, person)
	body, isError = h.call(t, "write", withApproval(map[string]any{"approval": code}))
	require.False(t, isError, "%v", body)
	require.Equal(t, "APPLIED", body["status"])
	require.Equal(t, json.Number("15"), body["rows"])
	require.Equal(t, "closed", leadStatus(t, d, 21))
	require.Equal(t, "closed", leadStatus(t, d, 35))

	pending, isError = h.call(t, "list_pending", map[string]any{})
	require.False(t, isError, "%v", pending)
	require.Empty(t, items(t, pending))

	body, isError = h.call(t, "write", withApproval(nil))
	requireToolError(t, body, isError, "APPROVAL_INVALID", "", "")
	require.Contains(t, body["message"], "already used")

	hist := h.history(t, runID)
	var applied int
	for _, rec := range hist {
		require.NotEqual(t, "APPROVAL_PENDING", rec["status"], "the held record is replaced by the applied one")
		if rec["status"] == "APPLIED" && rec["op"] == "UPDATE" {
			applied++
		}
	}
	require.Equal(t, 1, applied)
}

func TestHeldDeleteRelayedThroughBasaltApprove(t *testing.T) {
	t.Parallel()
	d, h, person, _ := approvalHarness(t)
	run, _ := h.call(t, "run_start", map[string]any{"intent": "Remove spam"})
	runID := str(t, run["runId"])
	args := map[string]any{"sql": "DELETE FROM leads WHERE id = $1", "params": []any{7}, "intent": "Lead 7 is spam", "runId": runID}

	body, isError := h.call(t, "write", args)
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
	ap := approvalOf(t, body)
	// The person relays the code with basalt approve (the agent credential).
	code := signLink(t, str(t, ap["approvalUrl"]), person)
	resp, err := approval.ParseResponse(code)
	require.NoError(t, err)
	_, err = guard.SubmitApproval(context.Background(), d.Admin, resp.ApprovalID, resp.Assertion())
	require.Error(t, err, "only agent roles relay")
	agentConn := d.NewAgent(t, "relay", leads, leads).Conn
	_, err = guard.SubmitApproval(context.Background(), agentConn, resp.ApprovalID, resp.Assertion())
	require.NoError(t, err)

	pending, _ := h.call(t, "list_pending", map[string]any{"status": "APPROVED"})
	require.Len(t, items(t, pending), 1)
	require.NotContains(t, items(t, pending)[0], "nextSteps", "an approved item needs nothing from the person: the agent applies it")

	args["approvalId"] = ap["approvalId"]
	body, isError = h.call(t, "write", args)
	require.False(t, isError, "%v", body)
	require.Zero(t, countLeads(t, d, 7))
}

func TestHeldWriteNotRepeatable(t *testing.T) {
	t.Parallel()
	d, h, _, sent := approvalHarness(t)
	body, isError := h.call(t, "write", map[string]any{
		"sql": "UPDATE leads SET name = name || to_char(now(), 'YYYY') WHERE id BETWEEN 40 AND 60", "intent": "stamp",
	})
	requireToolError(t, body, isError, "STATEMENT_REFUSED", "NOT_REPEATABLE", "")
	require.Contains(t, body["message"], "pass the value as a parameter")
	require.Empty(t, sent.sent)
	require.Equal(t, "lead 40", leadName(t, d, 40))

	// Under the hold limit the same statement is not held, so it applies.
	body, isError = h.call(t, "write", map[string]any{
		"sql": "UPDATE leads SET name = name || to_char(now(), 'YYYY') WHERE id = 40", "intent": "stamp one",
	})
	require.False(t, isError, "%v", body)
}

func TestHeldWriteOverFiftyRowsRefused(t *testing.T) {
	t.Parallel()
	_, h, _, sent := approvalHarness(t)
	body, isError := h.call(t, "write", map[string]any{"sql": "UPDATE leads SET score = 1 WHERE id <= 60", "intent": "bulk"})
	requireToolError(t, body, isError, "ROW_LIMIT_EXCEEDED", "", "BS003")
	require.Empty(t, sent.sent)
}

func countLeads(t *testing.T, d *guardtest.DB, id int) int {
	t.Helper()
	var n int
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT count(id) FROM public.leads WHERE id = $1`, id).Scan(&n))
	return n
}

func leadName(t *testing.T, d *guardtest.DB, id int) string {
	t.Helper()
	var s string
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT name FROM public.leads WHERE id = $1`, id).Scan(&s))
	return s
}
