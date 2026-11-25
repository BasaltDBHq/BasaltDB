package revert

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/textrule/textruletest"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver/mcptest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"
	"github.com/basaltdbhq/basaltdb/internal/testkit/stepcatalogtest"
)

// The revert cases of the error and result catalogs run here, on the revert
// use case: each builds the error or the result with the use case's own
// builders, and a REVERT_INVALID error gets its steps from InvalidSteps, the
// way the agent's Failure gives them. Their keys are stepcatalogtest's
// RevertErrorKeys and RevertResultKeys; the agent's tests cover the rest of
// the catalog and require these keys beside their own.

// testService is a service with what it takes to build it again under other
// options.
type testService struct {
	*Service
	t            *testing.T
	goos, config string
	opts         []option
}

func newTestService(t *testing.T, goos, config string, opts ...option) *testService {
	t.Helper()
	return &testService{Service: newService(t, goos, config, opts...), t: t, goos: goos, config: config, opts: opts}
}

// with is a new service over the same options and then opts.
func (s *testService) with(opts ...option) *Service {
	s.t.Helper()
	return newService(s.t, s.goos, s.config, append(append([]option(nil), s.opts...), opts...)...)
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

func guardRevert(detail string) func(*testing.T, *testService) error {
	return pgFail("BS005", "REVERT_INVALID", detail)
}

func plainFunc(f func() error) func(*testing.T, *testService) error {
	return func(*testing.T, *testService) error { return f() }
}

func nothingToRevert(tool string, lines []string, reason action.RevertReason, detail string, by uuid.UUID) func(*testing.T, *testService) error {
	return func(t *testing.T, s *testService) error {
		svc := s.with(withStore(catalogReverts{lines: lines, by: by}))
		scope := action.Scope{Kind: "RUN", ID: uuid.MustParse(caseRunID)}
		return svc.nothingToRevert(context.Background(), tool, scope, action.RevertRefusalError{Reason: reason, Detail: detail})
	}
}

// failure is what the agent's Failure does with err for the revert's cases:
// the error body, and the next steps and person message the catalog
// prescribes for it, from the use case's own builders.
func (s *testService) failure(tool string, args map[string]any, err error) *toolresult.ToolError {
	te := s.core.Errors.ToolError(err)
	entry, ok := guidance.Catalog().ErrorEntry(te.Code, te.Reason, tool)
	require.True(s.t, ok, "no catalog entry for %s %s %s", te.Code, te.Reason, tool)
	if len(te.NextSteps) == 0 {
		b := guidance.NewSteps()
		require.Equal(s.t, guidance.CodeRevertInvalid, te.Code, "only REVERT_INVALID takes its steps from here: %s %s", te.Code, te.Reason)
		id, _ := args[guidance.ArgRevertID].(string)
		InvalidSteps(b, te, id)
		steps, err := b.Build()
		require.NoError(s.t, err)
		te.NextSteps = steps
		if te.PersonMessage == "" {
			te.PersonMessage = guidance.FitToSteps("", steps)
		}
	}
	require.NoError(s.t, guidance.CheckPersonMessage(te.PersonMessage))
	require.Equal(s.t, entry.PersonMessage, te.PersonMessage != "", "person message agrees with the catalog")
	return te
}

// catalogCases are the revert's errors: one case per error entry of the
// catalog the use case builds.
func catalogCases() map[string]catalogCase {
	revertArgs := map[string]any{"revertId": caseRevertID}
	timeoutRevert := func(tool string) func(*testing.T, *testService) error {
		return func(t *testing.T, s *testService) error {
			return s.prepareTimeout(tool, action.Scope{Kind: "RUN", ID: uuid.MustParse(caseRunID)}, "57014")
		}
	}
	return map[string]catalogCase{
		stepcatalogtest.CaseKey("QUERY_TIMEOUT", "TIME_LIMIT", "preview_revert"): {
			"preview_revert",
			map[string]any{"runId": caseRunID},
			timeoutRevert("preview_revert"),
		},
		stepcatalogtest.CaseKey("QUERY_TIMEOUT", "TIME_LIMIT", "request_revert"): {
			"request_revert",
			map[string]any{"runId": caseRunID, "intent": "Undo"},
			timeoutRevert("request_revert"),
		},
		stepcatalogtest.CaseKey("REVERT_INVALID", "LINE_INVALID", ""): {
			"apply_revert_batch",
			map[string]any{"revertId": caseRevertID, "lines": []any{1}},
			guardRevert("line 9 is not in the plan"),
		},
		stepcatalogtest.CaseKey("REVERT_INVALID", "PLAN_NOT_SIGNED", ""): {
			"apply_revert_batch",
			map[string]any{"revertId": caseRevertID, "lines": []any{1}},
			guardRevert("the person has not signed this revert yet: they sign it on the revert page"),
		},
		stepcatalogtest.CaseKey("REVERT_INVALID", "PLAN_FINISHED", ""): {
			"apply_revert_batch",
			map[string]any{"revertId": caseRevertID, "lines": []any{1}},
			guardRevert("revert already applied: no line is pending"),
		},
		stepcatalogtest.CaseKey("REVERT_INVALID", "NOT_THIS_AGENT", ""): {
			"apply_revert_batch",
			map[string]any{"revertId": caseRevertID, "lines": []any{1}},
			guardRevert("no such revert"),
		},
		stepcatalogtest.CaseKey("REVERT_INVALID", "ROWS_CHANGED", ""): {"request_revert", revertArgs, func(t *testing.T, s *testService) error {
			return s.rowsChanged(caseRevert(false), "rows changed")
		}},
		stepcatalogtest.CaseKey("REVERT_INVALID", "BAD_SIGNATURE", ""): {"request_revert", revertArgs, func(t *testing.T, s *testService) error {
			return s.badSignatureWith(guidance.OpenLink(caseShortLink, signAgainText), caseRevert(false), "the code does not verify")
		}},
		stepcatalogtest.CaseKey("REVERT_INVALID", "PASSKEY_REVOKED", ""): {"request_revert", revertArgs, func(t *testing.T, s *testService) error {
			return s.passkeyRevokedWith(guidance.OpenLink(caseShortLink, signRevokedText), caseRevert(false))
		}},
		stepcatalogtest.CaseKey("REVERT_EXPIRED", "NOT_SIGNED", ""):   {"request_revert", revertArgs, func(t *testing.T, s *testService) error { return s.revertExpired(caseRevert(false)) }},
		stepcatalogtest.CaseKey("REVERT_EXPIRED", "NOT_FINISHED", ""): {"request_revert", revertArgs, func(t *testing.T, s *testService) error { return s.revertExpired(caseRevert(true)) }},
		stepcatalogtest.CaseKey("NOTHING_TO_REVERT", "READS_ONLY", ""): {
			"request_revert",
			map[string]any{"runId": caseRunID, "intent": "Undo"},
			nothingToRevert("request_revert", nil, action.RevertReadsOnly, "the run changed no rows", uuid.Nil),
		},
		stepcatalogtest.CaseKey("NOTHING_TO_REVERT", "ALL_CHANGED_BY_PEOPLE", ""): {
			"preview_revert",
			map[string]any{"runId": caseRunID},
			nothingToRevert("preview_revert", []string{changedAfterLine}, action.RevertNothing, "every line skipped", uuid.Nil),
		},
		stepcatalogtest.CaseKey("NOTHING_TO_REVERT", "ALREADY_REVERTED", ""): {
			"preview_revert",
			map[string]any{"runId": caseRunID},
			nothingToRevert("preview_revert", []string{alreadyRevertedLine}, action.RevertNothing, "every line skipped", uuid.MustParse(caseChangeID)),
		},
		stepcatalogtest.CaseKey("NOT_FOUND", "REVERT", ""): {"request_revert", revertArgs, plainFunc(func() error { return revertNotFound(uuid.MustParse(caseRevertID)) })},
		stepcatalogtest.CaseKey("NOT_FOUND", "TASK", ""): {
			"preview_revert",
			map[string]any{"taskId": caseRunID},
			plainFunc(func() error {
				return notOwnTask(action.Scope{Kind: "TASK", ID: uuid.MustParse(caseRunID)})
			}),
		},
	}
}

func TestRevertCatalogCasesAreTheOnesTheAgentExpects(t *testing.T) {
	t.Parallel()
	keys := make([]string, 0, len(catalogCases()))
	for k := range catalogCases() {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	require.Equal(t, stepcatalogtest.RevertErrorKeys(), keys)
	seen := map[string]bool{}
	for _, e := range stepcatalogtest.CatalogOf(t).Errors {
		seen[stepcatalogtest.EntryKey(e)] = true
	}
	for _, k := range keys {
		require.True(t, seen[k], "a case without a catalog entry: %s", k)
	}
}

func TestEveryRevertCatalogErrorGivesTheCatalogsSteps(t *testing.T) {
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
				s := newTestService(t, variant.goos, variant.config, withOperatedBy(variant.operatedBy), withStore(catalogReverts{}))
				te := s.failure(kase.tool, kase.args, kase.fail(t, s))
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

func caseBatchedRevert(t *testing.T, status string) action.Revert {
	t.Helper()
	r := caseRevert(true)
	r.Status, r.Batched, r.Rows, r.Skipped = status, true, 1209, 1
	r.BindingText = caseBindingText(t, true)
	apply := r.ExpiresAt.Add(24 * time.Hour)
	r.ApplyBy = &apply
	r.Progress = action.RevertProgress{Restored: 200, Skipped: 1, Pending: 1009}
	return r
}

func planItems(outcome string, nos ...int) []RevertPlanLine {
	out := make([]RevertPlanLine, 0, len(nos))
	for _, n := range nos {
		out = append(out, RevertPlanLine{RevertLine: action.RevertLine{No: n, Outcome: outcome}})
	}
	return out
}

func planGuidanceOf(t *testing.T, s *Service, r action.Revert, items []RevertPlanLine) (string, []toolresult.Link, []toolresult.NextStep) {
	t.Helper()
	plan := RevertPlan{Revert: r}
	plan.Page.Items = items
	if r.Status == ledger.RevertPending {
		n, err := s.revertNotice(context.Background(), r)
		require.NoError(t, err)
		plan.RevertURL, plan.PersonMessage, plan.Links = n.URL, n.Message, n.Links
	}
	person, steps, err := s.planGuidance(plan)
	require.NoError(t, err)
	return person, plan.Links, steps
}

// resultCases are the revert's results: one case per result entry of the
// catalog the use case builds.
func resultCases() map[string]resultCase {
	revertArgs := map[string]any{"revertId": caseRevertID}
	run := action.Scope{Kind: revert.ScopeRun, ID: uuid.MustParse(caseRunID)}
	task := action.Scope{Kind: revert.ScopeTask, ID: uuid.MustParse(caseRunID)}
	state := func(status string) func(*testing.T, *testService) (string, []toolresult.Link, []toolresult.NextStep) {
		return func(t *testing.T, s *testService) (string, []toolresult.Link, []toolresult.NextStep) {
			out, err := s.revertState(context.Background(), caseRevertWith(t, status))
			require.NoError(t, err)
			return out.PersonMessage, out.Links, out.NextSteps
		}
	}
	batch := func(status string) func(*testing.T, *testService) (string, []toolresult.Link, []toolresult.NextStep) {
		return func(t *testing.T, s *testService) (string, []toolresult.Link, []toolresult.NextStep) {
			person, steps, err := s.batchGuidance(action.BatchResult{
				RevertID: uuid.MustParse(caseRevertID), Batch: 5, Status: status, Restored: 1000, Skipped: 9,
			})
			require.NoError(t, err)
			return person, nil, steps
		}
	}
	tooLargeRevert := func(t *testing.T, s *testService) (*Service, action.Revert) {
		r := caseRevertWith(t, ledger.RevertPending)
		r.Lines, r.LinesLeftOut, r.LinesCost = nil, true, 2<<20
		return s.with(pagesOrigin("")), r
	}
	cases := map[string]resultCase{
		resultKey("request_revert", "REQUEST_TOO_LARGE"): {
			tool: "request_revert", args: map[string]any{"revertId": caseRevertID, "reissueLink": true},
			build: func(t *testing.T, s *testService) (string, []toolresult.Link, []toolresult.NextStep) {
				svc, r := tooLargeRevert(t, s)
				out, err := svc.revertWithLink(context.Background(), r)
				require.NoError(t, err)
				require.Equal(t, "http://localhost:8787/reverts/"+caseRevertID, out.RevertURL, "the page's address, no fragment")
				return out.PersonMessage, out.Links, out.NextSteps
			},
		},
		resultKey("revert_plan", "REQUEST_TOO_LARGE"): {
			tool: "revert_plan", args: revertArgs,
			build: func(t *testing.T, s *testService) (string, []toolresult.Link, []toolresult.NextStep) {
				svc, r := tooLargeRevert(t, s)
				n, err := svc.revertNotice(context.Background(), r)
				require.NoError(t, err)
				require.True(t, n.tooLarge)
				person, steps, err := svc.planGuidance(RevertPlan{Revert: r, RevertURL: n.URL, PersonMessage: n.Message, tooLarge: true})
				require.NoError(t, err)
				return person, nil, steps
			},
		},
		resultKey("preview_revert", "PREVIEW"): {
			tool: "preview_revert", args: map[string]any{"runId": caseRunID},
			build: func(t *testing.T, s *testService) (string, []toolresult.Link, []toolresult.NextStep) {
				person, steps, err := s.previewGuidance(RevertPreview{Scope: run, Rows: 3, Skipped: 1})
				require.NoError(t, err)
				return person, nil, steps
			},
		},
		resultKey("preview_revert", "PREVIEW_TASK"): {
			tool: "preview_revert", args: map[string]any{"taskId": caseRunID},
			build: func(t *testing.T, s *testService) (string, []toolresult.Link, []toolresult.NextStep) {
				person, steps, err := s.previewGuidance(RevertPreview{Scope: task, Rows: 3, Skipped: 1})
				require.NoError(t, err)
				return person, nil, steps
			},
		},
		resultKey("request_revert", "REQUESTED"): {
			tool: "request_revert", args: map[string]any{"runId": caseRunID, "intent": "Undo"},
			build: func(t *testing.T, s *testService) (string, []toolresult.Link, []toolresult.NextStep) {
				out, err := s.revertWithLink(context.Background(), caseRevertWith(t, ledger.RevertPending))
				require.NoError(t, err)
				return out.PersonMessage, out.Links, out.NextSteps
			},
		},
		resultKey("request_revert", "REQUESTED_NO_PAGES"): {
			tool: "request_revert", args: map[string]any{"runId": caseRunID, "intent": "Undo"},
			build: func(t *testing.T, s *testService) (string, []toolresult.Link, []toolresult.NextStep) {
				out, err := s.with(pagesOrigin("")).revertWithLink(context.Background(), caseRevertWith(t, ledger.RevertPending))
				require.NoError(t, err)
				return out.PersonMessage, out.Links, out.NextSteps
			},
		},
		resultKey("request_revert", "WAIT_ENDED"): {
			tool: "request_revert", args: revertArgs, openWithoutURL: true,
			build: state(ledger.RevertPending),
		},
		resultKey("request_revert", "APPLYING"): {tool: "request_revert", args: revertArgs, build: state(ledger.RevertApplying)},
		resultKey("request_revert", "APPLIED"):  {tool: "request_revert", args: revertArgs, build: state(ledger.RevertApplied)},
		resultKey("request_revert", "EXPIRED"):  {tool: "request_revert", args: revertArgs, build: state(ledger.RevertExpired)},
		resultKey("request_revert", "REJECTED"): {tool: "request_revert", args: revertArgs, build: state(ledger.RevertRejected)},
		resultKey("list_pending", "REVERT_PENDING"): {
			tool: "list_pending", args: map[string]any{}, openWithoutURL: true,
			build: func(t *testing.T, s *testService) (string, []toolresult.Link, []toolresult.NextStep) {
				p := &PendingRevert{Revert: caseRevertWith(t, ledger.RevertPending)}
				require.NoError(t, s.PendingRevert(context.Background(), p, false))
				return p.PersonMessage, p.Links, p.NextSteps
			},
		},
		resultKey("list_pending", "REVERT_APPLYING"): {
			tool: "list_pending", args: map[string]any{},
			build: func(t *testing.T, s *testService) (string, []toolresult.Link, []toolresult.NextStep) {
				p := &PendingRevert{Revert: caseBatchedRevert(t, ledger.RevertApplying)}
				require.NoError(t, s.PendingRevert(context.Background(), p, false))
				return p.PersonMessage, p.Links, p.NextSteps
			},
		},
		resultKey("revert_plan", "PENDING"): {
			tool: "revert_plan", args: revertArgs,
			build: func(t *testing.T, s *testService) (string, []toolresult.Link, []toolresult.NextStep) {
				return planGuidanceOf(t, s.Service, caseBatchedRevert(t, ledger.RevertPending), nil)
			},
		},
		resultKey("revert_plan", "APPLYING"): {
			tool: "revert_plan", args: revertArgs,
			build: func(t *testing.T, s *testService) (string, []toolresult.Link, []toolresult.NextStep) {
				return planGuidanceOf(t, s.Service, caseBatchedRevert(t, ledger.RevertApplying), planItems(guardmodel.OutcomePending, 202, 203, 204))
			},
		},
		resultKey("revert_plan", "APPLIED"): {
			tool: "revert_plan", args: revertArgs,
			build: func(t *testing.T, s *testService) (string, []toolresult.Link, []toolresult.NextStep) {
				return planGuidanceOf(t, s.Service, caseBatchedRevert(t, ledger.RevertApplied), nil)
			},
		},
		resultKey("revert_plan", "EXPIRED"): {
			tool: "revert_plan", args: revertArgs,
			build: func(t *testing.T, s *testService) (string, []toolresult.Link, []toolresult.NextStep) {
				return planGuidanceOf(t, s.Service, caseBatchedRevert(t, ledger.RevertExpired), nil)
			},
		},
		resultKey("revert_plan", "REJECTED"): {
			tool: "revert_plan", args: revertArgs,
			build: func(t *testing.T, s *testService) (string, []toolresult.Link, []toolresult.NextStep) {
				r := caseBatchedRevert(t, ledger.RevertRejected)
				r.RejectNote = "Not now."
				return planGuidanceOf(t, s.Service, r, nil)
			},
		},
		resultKey("apply_revert_batch", "APPLYING"): {
			tool: "apply_revert_batch", args: map[string]any{"revertId": caseRevertID, "lines": []any{1}},
			build: batch(ledger.RevertApplying),
		},
		resultKey("apply_revert_batch", "APPLIED"): {
			tool: "apply_revert_batch", args: map[string]any{"revertId": caseRevertID, "lines": []any{1}},
			build: batch(ledger.RevertApplied),
		},
	}
	return cases
}

// resultService is the service the result cases run on.
func resultService(t *testing.T, goos, config string) *testService {
	t.Helper()
	return newTestService(t, goos, config, pagesOrigin("http://localhost:7878"), withNow(time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)))
}

func TestRevertResultCasesAreTheOnesTheAgentExpects(t *testing.T) {
	t.Parallel()
	keys := make([]string, 0, len(resultCases()))
	for k := range resultCases() {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	require.Equal(t, stepcatalogtest.RevertResultKeys(), keys)
	seen := map[string]bool{}
	for _, e := range stepcatalogtest.CatalogOf(t).Results {
		seen[resultKey(e.Tool, e.Case)] = true
	}
	for _, k := range keys {
		require.True(t, seen[k], "a result case without a catalog entry: %s", k)
	}
}

func TestEveryRevertCatalogResultGivesTheCatalogsSteps(t *testing.T) {
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

func TestWaitEndedNamesTheLongLinkOnlyWithoutPages(t *testing.T) {
	t.Parallel()
	s := resultService(t, "linux", "")
	short, err := s.revertState(context.Background(), caseRevertWith(t, ledger.RevertPending))
	require.NoError(t, err)
	require.Empty(t, short.NextSteps[0].URL, "the short link was given earlier: no url")
	require.NotContains(t, short.PersonMessage, "http")

	long, err := s.with(pagesOrigin("")).revertState(context.Background(), caseRevertWith(t, ledger.RevertPending))
	require.NoError(t, err)
	require.NotEmpty(t, long.NextSteps[0].URL, "no pages: the long link is the only link")
}

func TestRequestedPersonMessageKeepsItsLimitWithALongIntent(t *testing.T) {
	t.Parallel()
	for _, pages := range []bool{true, false} {
		s := resultService(t, "linux", "")
		if !pages {
			s = newTestService(t, "linux", "", pagesOrigin(""), withNow(time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)))
		}
		n, err := s.revertNotice(context.Background(), caseRevertWith(t, ledger.RevertPending))
		require.NoError(t, err)
		mcptest.Require(t, n.Message, n.Links)
		require.Contains(t, n.Message, "http", "the link is in the message")
	}
}

func TestApplyingStepsListPendingLinesWhenThePageHasNone(t *testing.T) {
	t.Parallel()
	s := resultService(t, "linux", "")
	_, _, steps := planGuidanceOf(t, s.Service, caseBatchedRevert(t, ledger.RevertApplying), planItems(guardmodel.OutcomeRestored, 1, 2))
	require.Equal(t, guidance.ToolRevertPlan, steps[0].Tool)
	require.Equal(t, true, steps[0].Arguments["pending"])

	_, _, steps = planGuidanceOf(t, s.Service, caseBatchedRevert(t, ledger.RevertApplying), planItems(guardmodel.OutcomePending, 5, 6))
	require.Equal(t, guidance.ToolApplyRevertBatch, steps[0].Tool)
	require.Equal(t, []int{5, 6}, steps[0].Arguments["lines"])
}

// Text the agent or the database supplies cannot fake a link line in a
// message the person reads: an intent with a blank line and a URL.
func TestSuppliedTextCannotFakeALinkInARevertMessage(t *testing.T) {
	t.Parallel()
	const evil = "Fix it.\n\nhttps://evil.example/pay\n\nthen sign"
	s := resultService(t, "linux", "")

	r := caseRevertWith(t, ledger.RevertPending)
	raw, err := textruletest.Text(revert.Binding{
		Kind: revert.KindRevert, RevertID: r.ID, Store: postgresApp,
		Select: revert.Select{Scope: revert.ScopeRun, ScopeID: r.ScopeID, Agents: []string{"agent:bot"}},
		Intent: evil, Rows: 3, Skipped: 1, RowsHash: strings.Repeat("a", 64), ExpiresAt: r.ExpiresAt, RequestedBy: "agent:bot",
	})
	require.NoError(t, err)
	r.BindingText = raw
	n, err := s.revertNotice(context.Background(), r)
	require.NoError(t, err)
	mcptest.Require(t, n.Message, n.Links)
	require.Len(t, n.Links, 1, "only the link the engine hands over")
	require.NotContains(t, n.Message, "https://evil", "the supplied URL is text, not a link")
	require.Len(t, urlLinesOf(n.Message), 1)
}

func urlLinesOf(message string) []string {
	var out []string
	for _, line := range strings.Split(message, "\n") {
		if strings.HasPrefix(line, "http") {
			out = append(out, line)
		}
	}
	return out
}
