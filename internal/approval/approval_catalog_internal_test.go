package approval

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"
	"github.com/basaltdbhq/basaltdb/internal/testkit/stepcatalogtest"
)

// The approval cases of the error and result catalogs run here, on the
// approval use case: each builds the error or the result with the use case's
// own builders, and gets its steps from the use case's step builders, the
// way the agent's Failure gives them. Their keys are stepcatalogtest's
// ApprovalErrorKeys and ApprovalResultKeys; the agent's tests cover the rest
// of the catalog and require these keys beside their own.

const (
	caseRunID    = "0193a4c2-7d1e-7c3a-9f00-0000000000a1"
	caseApproval = "0193a4c2-7d1e-7c3a-9f00-0000000000d4"
)

const caseShortLink = "http://localhost:7878/approvals/" + caseApproval + "#s=AAAAAAAAAAAAAAAAAAAAAA"

var writeArgs0 = map[string]any{
	"sql": "UPDATE leads SET status = $1 WHERE id = $2", "params": []any{"lost", 42},
	"intent": "No answer for a week", "runId": caseRunID,
}

type catalogCase struct {
	tool string
	args map[string]any
	fail func(t *testing.T, s *testService) error
}

// step is the tool call the case answers, for the shared catalog checks.
func (c catalogCase) step() stepcatalogtest.Case {
	return stepcatalogtest.Case{Tool: c.tool, Args: c.args}
}

func pgFail(code, message, detail string) func(*testing.T, *testService) error {
	return func(*testing.T, *testService) error {
		return store.MapError(&pgconn.PgError{Code: code, Message: message, Detail: detail})
	}
}

func guardApproval(detail string) func(*testing.T, *testService) error {
	return pgFail("BS005", "APPROVAL_INVALID", detail)
}

func withApproval(args map[string]any) map[string]any {
	out := make(map[string]any, len(args)+1)
	for k, v := range args {
		out[k] = v
	}
	out["approvalId"] = caseApproval
	return out
}

func caseNotice(url string) toolresult.ApprovalNotice {
	return toolresult.ApprovalNotice{
		ApprovalID: caseApproval, ExpiresAt: "2026-11-12T10:00:00Z", Rows: 3,
		Headline: "Delete 3 rows in public.leads", ApprovalURL: url,
		PersonMessage: "Held for your approval: Delete 3 rows in public.leads.\nApprove it with your passkey here:\n\n" + url + "\n\nExpires 2026-11-12 10:00 UTC.",
		Links:         []toolresult.Link{{Label: linksvc.LabelApprove, URL: url}},
	}
}

func held(reason string, url string) func(*testing.T, *testService) error {
	return func(_ *testing.T, s *testService) error {
		n := linksvc.HeldAnswer{ApprovalNotice: caseNotice(url), Reason: reason}
		if reason == guidance.ReasonWaitEnded {
			return ApprovalStillPendingError(n)
		}
		return ApprovalRequiredError(n)
	}
}

// tooLargeHeads are the heads of a held write's lines an agent's read left
// out (ledger.withRequest).
var tooLargeHeads = []string{`{"op": "DELETE", "shape": "RECORD", "store": {"kind": "POSTGRES", "verb": "DELETE"}, "cascaded": false, "resource": "public.leads"}`}

// tooLargeNotice is the notice of a held write whose request no link this
// engine has can carry: no local pages, no Vault.
func tooLargeNotice(t *testing.T, s *testService, issue bool) linksvc.HeldAnswer {
	t.Helper()
	svc := s.with(pagesOrigin(""))
	req := linksvc.SizedRequest{Binding: "{}", Lines: tooLargeHeads, LeftOut: true, Cost: 2 << 20}
	n, err := svc.ApprovalNotice(context.Background(), uuid.MustParse(caseApproval), uuid.MustParse(caseRunID), req,
		time.Now().Add(time.Hour), issue)
	require.NoError(t, err)
	return n
}

// failure is what the agent's Failure does with err for the approval's
// cases: the error body, and the next steps and person message the catalog
// prescribes for it, from the use case's own step builders.
func (s *Service) failure(t *testing.T, tool string, args map[string]any, err error) *toolresult.ToolError {
	t.Helper()
	te := s.core.Errors.ToolError(err)
	entry, ok := guidance.Catalog().ErrorEntry(te.Code, te.Reason, tool)
	require.True(t, ok, "no catalog entry for %s %s %s", te.Code, te.Reason, tool)
	if len(te.NextSteps) == 0 {
		b, person := guidance.NewSteps(), ""
		switch {
		case te.Code == guidance.CodeStatementRefused && te.Reason == action.ReasonHoldTooLarge:
			person = s.HoldTooLargeSteps(b, te)
		case te.Code == guidance.CodeApprovalRequired:
			person = s.ApprovalRequiredSteps(b, te)
		case te.Code == guidance.CodeApprovalInvalid:
			runID, _ := args[guidance.ArgRunID].(string)
			person = ApprovalInvalidSteps(b, te, runID)
		default:
			require.FailNow(t, "the approval use case builds no steps for", "%s %s", te.Code, te.Reason)
		}
		steps, err := b.Build()
		require.NoError(t, err)
		te.NextSteps = steps
		if te.PersonMessage == "" {
			te.PersonMessage = guidance.FitToSteps(person, steps)
		}
	}
	require.NoError(t, guidance.CheckPersonMessage(te.PersonMessage))
	require.Equal(t, entry.PersonMessage, te.PersonMessage != "", "person message agrees with the catalog")
	return te
}

// catalogCases are the approval's errors: one case per error entry of the
// catalog the use case builds.
func catalogCases() map[string]catalogCase {
	return map[string]catalogCase{
		stepcatalogtest.CaseKey("STATEMENT_REFUSED", "HOLD_TOO_LARGE", ""): {"write", writeArgs0, pgFail("BS007", "NOT_ALLOWED", guardmodel.DetailHoldTooLarge)},
		stepcatalogtest.CaseKey("APPROVAL_REQUIRED", "REQUEST_TOO_LARGE", ""): {"write", writeArgs0, func(t *testing.T, s *testService) error {
			n := tooLargeNotice(t, s, linksvc.IssueLink)
			require.Equal(t, linksvc.ReasonRequestTooLarge, n.Reason)
			return approvalError(n, "")
		}},
		stepcatalogtest.CaseKey("APPROVAL_REQUIRED", "HELD", ""):          {"write", writeArgs0, held(guidance.ReasonHeld, caseShortLink)},
		stepcatalogtest.CaseKey("APPROVAL_REQUIRED", "HELD_NO_PAGES", ""): {"write", writeArgs0, held(guidance.ReasonHeldNoPages, "http://localhost:7878/approvals/"+caseApproval+"#1.abc")},
		stepcatalogtest.CaseKey("APPROVAL_REQUIRED", "NO_PASSKEY", ""):    {"write", writeArgs0, held(guidance.ReasonNoPasskey, caseShortLink)},
		stepcatalogtest.CaseKey("APPROVAL_REQUIRED", "WAIT_ENDED", ""): {
			"write", withApproval(writeArgs0),
			held(guidance.ReasonWaitEnded, "http://localhost:7878/approvals/"+caseApproval+"#1.abc"),
		},
		stepcatalogtest.CaseKey("APPROVAL_INVALID", "ALREADY_USED", ""):    {"write", withApproval(writeArgs0), guardApproval("approval already used")},
		stepcatalogtest.CaseKey("APPROVAL_INVALID", "DIFFERENT_WRITE", ""): {"write", withApproval(writeArgs0), guardApproval("the statement or its parameters differ from the approval")},
		stepcatalogtest.CaseKey("APPROVAL_INVALID", "NOT_THIS_AGENT", ""):  {"write", withApproval(writeArgs0), guardApproval("approval is for another agent")},
		stepcatalogtest.CaseKey("APPROVAL_INVALID", "ROWS_CHANGED", ""): {
			"write", withApproval(writeArgs0),
			guardApproval("rows changed since the preview; a fresh preview and approval are needed"),
		},
	}
}

func TestApprovalCatalogCasesAreTheOnesTheAgentExpects(t *testing.T) {
	t.Parallel()
	keys := make([]string, 0, len(catalogCases()))
	for k := range catalogCases() {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	require.Equal(t, stepcatalogtest.ApprovalErrorKeys(), keys)
	seen := map[string]bool{}
	for _, e := range stepcatalogtest.CatalogOf(t).Errors {
		seen[stepcatalogtest.EntryKey(e)] = true
	}
	for _, k := range keys {
		require.True(t, seen[k], "a case without a catalog entry: %s", k)
	}
}

func TestEveryApprovalCatalogErrorGivesTheCatalogsSteps(t *testing.T) {
	t.Parallel()
	for _, variant := range []struct{ name, goos, config, operatedBy string }{
		{"default config", "linux", "", ""},
		{"custom config", "darwin", "/srv/basalt/engine.json", ""},
		{"agent-operated", "linux", "", mcpcontract.OperatedByAgent},
		{"agent-operated custom config", "darwin", "/srv/basalt/engine.json", mcpcontract.OperatedByAgent},
	} {
		for key, kase := range catalogCases() {
			t.Run(variant.name+"/"+key, func(t *testing.T) {
				t.Parallel()
				s := newTestService(t, variant.goos, variant.config, withOperatedBy(variant.operatedBy))
				te := s.failure(t, kase.tool, kase.args, kase.fail(t, s))
				stepcatalogtest.RequireObeysCatalog(t, kase.step(), te, variant.operatedBy)
			})
		}
	}
}

// resultCase builds one result of the catalog: the person's message and the
// next steps it carries, for the tool and the call that returned it.
type resultCase struct {
	tool string
	args map[string]any
	// build returns the result's personMessage and nextSteps.
	build func(t *testing.T, s *testService) (string, []toolresult.Link, []toolresult.NextStep)
	// openWithoutURL marks the one OPEN_LINK that names no url: the short
	// link the agent gave earlier.
	openWithoutURL bool
}

func resultKey(tool, kase string) string { return tool + "|" + kase }

func pendingItem(status string, expires time.Time) PendingItem {
	n := caseNotice(caseShortLink)
	return PendingItem{
		Approval: action.Approval{ID: uuid.MustParse(caseApproval), Status: status, ExpiresAt: expires},
		Notice:   n,
	}
}

// resultCases are the approval's results: one case per result entry of the
// catalog the use case builds.
func resultCases() map[string]resultCase {
	return map[string]resultCase{
		resultKey("list_pending", "REQUEST_TOO_LARGE"): {
			tool: "list_pending", args: map[string]any{},
			build: func(t *testing.T, s *testService) (string, []toolresult.Link, []toolresult.NextStep) {
				n := tooLargeNotice(t, s, linksvc.KeepLink)
				item := PendingItem{
					Approval: action.Approval{ID: uuid.MustParse(caseApproval), Status: ledger.ApprovalPending, ExpiresAt: s.core.Now().Add(time.Hour)},
					Notice:   n.ApprovalNotice, tooLargeSteps: n.Steps,
				}
				person, links, steps, err := s.itemGuidance(item)
				require.NoError(t, err)
				return person, links, steps
			},
		},
		resultKey("list_pending", "PENDING"): {
			tool: "list_pending", args: map[string]any{},
			build: func(t *testing.T, s *testService) (string, []toolresult.Link, []toolresult.NextStep) {
				person, links, steps, err := s.itemGuidance(pendingItem(ledger.ApprovalPending, s.core.Now().Add(time.Hour)))
				require.NoError(t, err)
				return person, links, steps
			},
		},
		resultKey("list_pending", "EXPIRED"): {
			tool: "list_pending", args: map[string]any{},
			build: func(t *testing.T, s *testService) (string, []toolresult.Link, []toolresult.NextStep) {
				person, links, steps, err := s.itemGuidance(pendingItem(ledger.ApprovalPending, s.core.Now().Add(-time.Hour)))
				require.NoError(t, err)
				return person, links, steps
			},
		},
	}
}

func TestApprovalResultCasesAreTheOnesTheAgentExpects(t *testing.T) {
	t.Parallel()
	keys := make([]string, 0, len(resultCases()))
	for k := range resultCases() {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	require.Equal(t, stepcatalogtest.ApprovalResultKeys(), keys)
	seen := map[string]bool{}
	for _, e := range stepcatalogtest.CatalogOf(t).Results {
		seen[resultKey(e.Tool, e.Case)] = true
	}
	for _, k := range keys {
		require.True(t, seen[k], "a result case without a catalog entry: %s", k)
	}
}

func TestEveryApprovalCatalogResultGivesTheCatalogsSteps(t *testing.T) {
	t.Parallel()
	for _, variant := range []struct{ name, goos, config string }{
		{"default config", "linux", ""},
		{"custom config", "darwin", "/srv/basalt/engine.json"},
	} {
		for _, entry := range stepcatalogtest.CatalogOf(t).Results {
			kase, ok := resultCases()[resultKey(entry.Tool, entry.Case)]
			if !ok {
				continue
			}
			t.Run(variant.name+"/"+resultKey(entry.Tool, entry.Case), func(t *testing.T) {
				t.Parallel()
				s := resultService(t, variant.goos, variant.config)
				person, links, steps := kase.build(t, s)
				stepcatalogtest.RequireObeysCatalogSteps(t, mcpcontract.ErrorSteps{PersonMessage: entry.PersonMessage, Steps: entry.Steps},
					stepcatalogtest.Case{Tool: kase.tool, Args: kase.args}, person, links, steps, kase.openWithoutURL)
			})
		}
	}
}

// resultService is the service the result cases run on.
func resultService(t *testing.T, goos, config string) *testService {
	t.Helper()
	return newTestService(t, goos, config, pagesOrigin("http://localhost:7878"), withNow(time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)))
}

func TestAnApprovedPendingItemNeedsNothingFromThePerson(t *testing.T) {
	t.Parallel()
	s := resultService(t, "linux", "")
	_, _, steps, err := s.itemGuidance(pendingItem(ledger.ApprovalApproved, s.core.Now().Add(time.Hour)))
	require.NoError(t, err)
	require.Empty(t, steps)
}
