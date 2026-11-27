package servedagent_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentsvc "github.com/basaltdbhq/basaltdb/internal/agent"
	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/config"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/basaltdbhq/basaltdb/internal/testkit/agenttest"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/approval/approvaltest"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver/mcptest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"
)

// notices records what the engine hands its Notifier.
type notices struct {
	mu      sync.Mutex
	sent    []linksvc.HeldNotice
	reverts []linksvc.RevertNotice
}

func (n *notices) NotifyRevert(_ context.Context, r linksvc.RevertNotice) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.reverts = append(n.reverts, r)
	return nil
}

// revertNotices returns what the engine sent about reverts so far.
func (n *notices) revertNotices() []linksvc.RevertNotice {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]linksvc.RevertNotice(nil), n.reverts...)
}

func (n *notices) NotifyHeld(_ context.Context, h linksvc.HeldNotice) error {
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
	svc    *app.Service
	blind  *agentsvc.BlindCache
	// finds counts the agent's approval reads: one when a call looks its
	// approval up, one more for every poll while it waits.
	finds *finds
	// revertFinds is the same for the revert the agent waits on.
	revertFinds *revertFinds
	// keys sign the engine's receipts; nil for an engine whose key file is
	// refused (KEY_ERROR).
	keys *channel.EngineKeys
}

// finds wraps the store and counts FindApproval calls, so a test can tell
// that the agent is waiting without guessing a delay.
type finds struct {
	app.SQLStore
	n atomic.Int64
}

func (f *finds) FindApproval(ctx context.Context, id uuid.UUID) (action.Approval, error) {
	f.n.Add(1)
	return f.SQLStore.FindApproval(ctx, id)
}

// revertFinds wraps the store and counts FindRevert calls.
type revertFinds struct {
	app.SQLStore
	n atomic.Int64
}

func (f *revertFinds) FindRevert(ctx context.Context, id uuid.UUID) (action.Revert, error) {
	f.n.Add(1)
	return f.SQLStore.FindRevert(ctx, id)
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
	keys, err := channel.GenerateEngineKeys(time.Now)
	require.NoError(t, err)
	return agentHarnessKeys(t, d, a, keys, pagesOrigin...)
}

// agentHarnessKeys is agentHarnessFor with the engine's keys: nil is an
// engine whose key file is refused (KEY_ERROR), which signs no receipt.
func agentHarnessKeys(t *testing.T, d *guardtest.DB, a *guardtest.Agent, keys *channel.EngineKeys, pagesOrigin ...string) agentEnv {
	t.Helper()
	return agentHarnessLimits(t, d, a, keys, sqlguard.DefaultLimits(), pagesOrigin...)
}

// agentHarnessLimits is agentHarnessKeys with the agent's limits.
func agentHarnessLimits(t *testing.T, d *guardtest.DB, a *guardtest.Agent, keys *channel.EngineKeys, limits sqlguard.Limits, pagesOrigin ...string) agentEnv {
	t.Helper()
	return agentHarnessWith(t, d, a, keys, limits, nil, pagesOrigin...)
}

// agentHarnessWith is agentHarnessLimits with an edit of the dependencies,
// made before the service is built, so every use case reads it.
func agentHarnessWith(t *testing.T, d *guardtest.DB, a *guardtest.Agent, keys *channel.EngineKeys, limits sqlguard.Limits, edit func(*app.Deps), pagesOrigin ...string) agentEnv {
	t.Helper()
	var receipts linksvc.ReceiptSigner
	if keys != nil {
		receipts = keys
	}
	// The person's passkey is on the pages the agent's links open: the
	// default local pages, as the service has no other pages base.
	rp, err := passkey.Local(links.DefaultLocal)
	require.NoError(t, err)
	person, err := passkeytest.New(rp)
	require.NoError(t, err)
	require.NoError(t, guard.RegisterPasskey(context.Background(), d.Admin, person.Credential(), "app"))

	// The engine's commands for bot on linux: a valid name and an absolute
	// config path pass app's checks, so they are guidance.NewCommands' own.
	cmds := guidance.NewCommands("bot", "/etc/basalt-test/engine.json", config.DefaultPath("linux"), "linux", agenttest.ServiceManager())
	sent := &notices{}
	var watched *finds
	var watchedReverts *revertFinds
	var blind *agentsvc.BlindCache
	// As the engine runs it: every read of a call charged to its budget.
	svc := agenttest.PgService(t, a.URL, agenttest.WithLimits(limits), agenttest.WithBudget(), agenttest.WithDeps(func(d *app.Deps, pool *pgxpool.Pool) {
		watched = &finds{SQLStore: d.Core.Store.(app.SQLStore)}
		watchedReverts = &revertFinds{SQLStore: watched}
		blind = agentsvc.NewBlindCache(func(ctx context.Context, tables []string) ([]string, error) {
			return guard.RLSBlindTables(ctx, pool, "", tables)
		})
		agenttest.UseStore(d, watchedReverts)
		d.Delivery.Notifier = sent
		d.Approval.Columns = store.NewColumnOrder(pool)
		d.Core.Commands, d.Core.PagesOrigin, d.Delivery.Poll, d.Agent.Visibility, d.Delivery.Receipts = cmds, strings.Join(pagesOrigin, ""), testPoll, blind, receipts
		if edit != nil {
			edit(d)
		}
	})).Svc
	return agentEnv{d: d, a: a, h: harness{server: mcpserver.NewServer(mcpserver.Info{Name: "basalt"}, app.AgentTools(svc)...)}, person: person, sent: sent, svc: svc, blind: blind, finds: watched, revertFinds: watchedReverts, keys: keys}
}

func approvalOf(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	ap, ok := body["approval"].(map[string]any)
	require.True(t, ok, "%v", body)
	return ap
}

// signLink does what the person does on the approval page: decode the
// link, check it, and sign the binding with the passkey.
func signLink(t *testing.T, link string, signer *passkeytest.Authenticator) approval.Response {
	t.Helper()
	frag := link[strings.Index(link, "#")+1:]
	req, b, err := approvaltest.ParseRequest(frag)
	require.NoError(t, err)
	require.NotEmpty(t, req.CredentialIDs, "the link names the database's passkeys, for allowCredentials")
	as, err := signer.Sign(passkeytest.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	return approvaltest.NewResponse(b.ApprovalID, as)
}

// reviewOnlyText is what a message that hands over a long link says: with
// no page that can carry a signature, the person can only review.
const reviewOnlyText = "Review only: this link cannot be signed. Ask the agent for a new link later."

// relayApproval is what the approval page does after the passkey signed:
// it posts the signature, which the engine relays to Postgres
// (RelayApproval), on its own pages or through the Vault. Nothing is pasted.
func relayApproval(svc *app.Service, resp approval.Response) error {
	_, err := svc.RelayApproval(context.Background(), resp)
	return err
}

func TestHeldWriteApprovedWithPasskey(t *testing.T) {
	t.Parallel()
	e := agentHarness(t)
	d, h, person, sent := e.d, e.h, e.person, e.sent
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
	require.NotContains(t, ap, "approveCommand", "the person acts on the link, never a command")
	require.Contains(t, str(t, body["message"]), "Show the person approval.personMessage verbatim")
	require.Contains(t, str(t, body["message"]), "without ending your turn, call write once with the same arguments plus approvalId")
	require.Contains(t, str(t, body["message"]), "do not wait again")
	require.Equal(t, "Update 15 rows in public.leads", ap["headline"])
	require.True(t, strings.HasPrefix(str(t, ap["personMessage"]),
		"Held for your approval: Update 15 rows in public·leads.\n"+reviewOnlyText+"\n\n"+
			link+"\n\nExpires "),
		"without local pages and within the budget the message carries the long link: %v", ap["personMessage"])
	mcptest.Require(t, str(t, ap["personMessage"]), mcptest.LinksOf(t, ap))
	require.Equal(t, []toolresult.Link{{Label: "Approve the held write", URL: link}}, mcptest.LinksOf(t, ap))
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
	require.NotContains(t, list[0], "approveCommand")
	require.Equal(t, ap["personMessage"], list[0]["personMessage"], "list_pending gives the link back")
	require.Equal(t, ap["links"], list[0]["links"])
	mcptest.Require(t, str(t, list[0]["personMessage"]), mcptest.LinksOf(t, list[0]))
	require.Equal(t, ap["headline"], list[0]["headline"])
	pendingSteps := requireToolSteps(t, list[0], "list_pending", "PENDING")
	require.Equal(t, link, pendingSteps[0]["url"])
	require.Nil(t, pendingSteps[0]["command"], "the step is the link alone")
	require.Equal(t, []any{"status"}, list[0]["assignedFields"])

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
	err = relayApproval(e.svc, signLink(t, link, forger))
	require.Error(t, err)
	require.Equal(t, "APPROVAL_INVALID", agenttest.ToolError(err).Code, "%v", err)
	body, isError = h.call(t, "write", withApproval(map[string]any{"waitForApproval": 0}))
	requireToolError(t, body, isError, "APPROVAL_INVALID", "", "")
	require.Contains(t, body["message"], "not approved yet", "a forged signature approves nothing")

	body, isError = h.call(t, "write", withApproval(map[string]any{"params": []any{"closed", 21, 36}}))
	requireToolError(t, body, isError, "APPROVAL_INVALID", "", "")
	require.Contains(t, body["message"], "the request must be exactly the held write's")

	require.NoError(t, relayApproval(e.svc, signLink(t, link, person)))
	body, isError = h.call(t, "write", withApproval(nil))
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

// Only an agent role relays a signature: the engine relays it with the
// agent's credential, never the admin's.
func TestHeldDeleteRelayedWithTheAgentsCredential(t *testing.T) {
	t.Parallel()
	d, h, person, _ := approvalHarness(t)
	run, _ := h.call(t, "run_start", map[string]any{"intent": "Remove spam"})
	runID := str(t, run["runId"])
	args := map[string]any{"sql": "DELETE FROM leads WHERE id = $1", "params": []any{7}, "intent": "Lead 7 is spam", "runId": runID}

	body, isError := h.call(t, "write", args)
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
	ap := approvalOf(t, body)
	resp := signLink(t, str(t, ap["approvalUrl"]), person)
	_, err := guard.SubmitApproval(context.Background(), d.Admin, resp.ApprovalID, resp.Assertion())
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

// A held write whose values change between runs and cannot be fixed is
// refused, naming the function; under the hold limit it is not held, so it
// applies.
func TestHeldWriteNotRepeatable(t *testing.T) {
	t.Parallel()
	d, h, _, sent := approvalHarness(t)
	body, isError := h.call(t, "write", map[string]any{
		"sql": "UPDATE leads SET score = (random() * 10)::int WHERE id BETWEEN 40 AND 60", "intent": "shuffle",
	})
	requireToolError(t, body, isError, "STATEMENT_REFUSED", "NOT_REPEATABLE", "")
	require.Contains(t, body["message"], "random()")
	require.Contains(t, body["message"], "pass the value as a parameter")
	require.Empty(t, sent.sent)
	require.Equal(t, "lead 40", leadName(t, d, 40))

	body, isError = h.call(t, "write", map[string]any{
		"sql": "UPDATE leads SET score = (random() * 10)::int WHERE id = 40", "intent": "shuffle one",
	})
	require.False(t, isError, "%v", body)
}

// approveHeld signs the held write body answered with and relays the
// signature, as the person does on the page.
func approveHeld(t *testing.T, e agentEnv, body map[string]any) string {
	t.Helper()
	ap := approvalOf(t, body)
	require.NoError(t, relayApproval(e.svc, signLink(t, str(t, ap["approvalUrl"]), e.person)))
	return str(t, ap["approvalId"])
}

// now() in a held write is evaluated once, when the write is held: the held
// statement, the preview and the applied rows carry the same value, and the
// agent sends its own statement again with the approval.
func TestHeldWriteFixesNow(t *testing.T) {
	t.Parallel()
	e := agentHarness(t)
	run, _ := e.h.call(t, "run_start", map[string]any{"intent": "Stamp the stale leads"})
	args := map[string]any{
		"sql":    "UPDATE leads SET status = now()::text WHERE id BETWEEN 21 AND 45",
		"intent": "Mark when leads 21 to 45 were reviewed", "runId": str(t, run["runId"]),
	}
	body, isError := e.h.call(t, "write", args)
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
	require.Len(t, e.sent.sent, 1)
	held := e.sent.sent[0].Statement
	require.NotContains(t, held, "now()", "the held statement carries the fixed time")
	require.Contains(t, held, "::timestamp with time zone")
	require.Equal(t, "open", leadStatus(t, e.d, 21), "a held write changes nothing")

	args["approvalId"] = approveHeld(t, e, body)
	body, isError = e.h.call(t, "write", args)
	require.False(t, isError, "%v", body)
	require.Equal(t, "APPLIED", body["status"])
	require.Equal(t, json.Number("25"), body["rows"])

	var values []string
	rows, err := e.d.Admin.Query(context.Background(), `SELECT DISTINCT status FROM public.leads WHERE id BETWEEN 21 AND 45`)
	require.NoError(t, err)
	for rows.Next() {
		var v string
		require.NoError(t, rows.Scan(&v))
		values = append(values, v)
	}
	require.NoError(t, rows.Err())
	require.Len(t, values, 1, "every row has the one fixed time")
	require.Contains(t, held, "'"+values[0]+"'", "the applied value is the one the person approved")
}

// elevenLeads is an INSERT of eleven new leads from id first, without a
// column list (the harness seeds leads 1 to 200).
func elevenLeads(first int) string {
	var b strings.Builder
	b.WriteString("INSERT INTO leads VALUES ")
	for id := first; id < first+11; id++ {
		if id > first {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "(%d, 'lead %d')", id, id)
	}
	return b.String()
}

// A held INSERT without a column list binds every column: a column it
// leaves to a now() default gets the fixed time, so the write applies as
// approved. A column left to a default that changes on every run is
// refused, naming it.
func TestHeldInsertFixesTimeDefaults(t *testing.T) {
	t.Parallel()
	e := agentHarness(t)
	e.d.Exec(t, `ALTER TABLE public.leads ADD COLUMN seen timestamptz NOT NULL DEFAULT now()`)
	run, _ := e.h.call(t, "run_start", map[string]any{"intent": "Add leads"})
	args := map[string]any{"sql": elevenLeads(301), "intent": "Eleven new leads", "runId": str(t, run["runId"])}
	body, isError := e.h.call(t, "write", args)
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
	require.Contains(t, e.sent.sent[0].Statement, "seen", "the held INSERT names the column it fixed")

	args["approvalId"] = approveHeld(t, e, body)
	body, isError = e.h.call(t, "write", args)
	require.False(t, isError, "%v", body)
	require.Equal(t, "APPLIED", body["status"])
	var n, seen int
	require.NoError(t, e.d.Admin.QueryRow(context.Background(),
		`SELECT count(*), count(DISTINCT seen) FROM public.leads WHERE id BETWEEN 301 AND 311`).Scan(&n, &seen))
	require.Equal(t, 11, n)
	require.Equal(t, 1, seen, "one fixed time for every row")

	e.d.Exec(t, `ALTER TABLE public.leads ADD COLUMN token uuid DEFAULT gen_random_uuid()`)
	body, isError = e.h.call(t, "write", map[string]any{"sql": elevenLeads(401), "intent": "More leads"})
	requireToolError(t, body, isError, "STATEMENT_REFUSED", "NOT_REPEATABLE", "")
	require.Contains(t, body["message"], `"token"`)
	require.Contains(t, body["message"], "list the columns")

	// A default that calls a volatile function of the app's (or of an
	// extension) is refused the same way, from pg_proc.provolatile.
	e.d.Exec(t, `ALTER TABLE public.leads DROP COLUMN token`)
	e.d.Exec(t, `CREATE FUNCTION public.new_ref() RETURNS text LANGUAGE sql VOLATILE AS $$ SELECT md5(random()::text) $$`)
	e.d.Exec(t, `ALTER TABLE public.leads ADD COLUMN ref text DEFAULT public.new_ref()`)
	body, isError = e.h.call(t, "write", map[string]any{"sql": elevenLeads(401), "intent": "More leads"})
	requireToolError(t, body, isError, "STATEMENT_REFUSED", "NOT_REPEATABLE", "")
	require.Contains(t, body["message"], `"ref"`)
	require.Contains(t, body["message"], "new_ref()")
}

// A time word as a bare literal or as a parameter is read as the current time
// when Postgres runs the write, so a held write with one could never apply.
func TestHeldWriteWithATimeWordNotRepeatable(t *testing.T) {
	t.Parallel()
	_, h, _, sent := approvalHarness(t)
	for _, args := range []map[string]any{
		{"sql": "UPDATE leads SET status = 'now' WHERE id BETWEEN 40 AND 60", "intent": "stamp"},
		{"sql": "UPDATE leads SET status = 'Tomorrow 10:00' WHERE id BETWEEN 40 AND 60", "intent": "stamp"},
		{"sql": "UPDATE leads SET status = $1 WHERE id BETWEEN 40 AND 60", "params": []any{"now"}, "intent": "stamp"},
		{"sql": "UPDATE leads SET status = $1 WHERE id BETWEEN 40 AND 60", "params": []any{"today"}, "intent": "stamp"},
	} {
		body, isError := h.call(t, "write", args)
		requireToolError(t, body, isError, "STATEMENT_REFUSED", "NOT_REPEATABLE", "")
		require.Contains(t, body["message"], "parameter")
	}
	require.Empty(t, sent.sent)
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
