package agent

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver/mcptest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
)

// resultCase builds one result of the catalog: the person's message and the
// next steps it carries, for the tool and the call that returned it.
type resultCase struct {
	tool string
	args map[string]any
	// build returns the result's personMessage and nextSteps.
	build func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep)
	// openWithoutURL marks the one OPEN_LINK that names no url: the short
	// link the agent gave earlier.
	openWithoutURL bool
}

type fakeRLS struct {
	hidden map[string]bool
	err    error
	asked  int
}

// Hides names a hidden table as the database does: quoted.
func (f *fakeRLS) Hides(_ context.Context, table string) (string, error) {
	f.asked++
	if f.hidden[table] {
		return `"` + strings.ReplaceAll(table, ".", `"."`) + `"`, f.err
	}
	return "", f.err
}

type fakeUpgrade struct {
	available bool
	err       error
}

func (f fakeUpgrade) UpgradeAvailable(context.Context) (bool, error) { return f.available, f.err }

func resultKey(tool, kase string) string { return tool + "|" + kase }

func caseBindingText(t *testing.T, batched bool) string {
	t.Helper()
	rows, skipped := 3, 1
	if batched {
		rows, skipped = 1209, 1
	}
	raw, err := json.Marshal(revert.Binding{
		Kind: revert.KindRevert, RevertID: uuid.MustParse(caseRevertID), Database: "app",
		Select: revert.Select{Scope: revert.ScopeRun, ScopeID: uuid.MustParse(caseRunID), Agents: []string{"bot"}}, Intent: strings.Repeat("The agent set the wrong status. ", 30),
		Rows: rows, Skipped: skipped, RowsHash: strings.Repeat("a", 64), ExpiresAt: caseRevert(false).ExpiresAt, RequestedBy: "bot",
		Batched: batched, SampleHash: map[bool]string{true: strings.Repeat("b", 64)}[batched],
	})
	require.NoError(t, err)
	return string(raw)
}

func caseRevertWith(t *testing.T, status string) action.Revert {
	t.Helper()
	r := caseRevert(false)
	r.Status, r.Rows, r.Skipped, r.BindingText = status, 3, 1, caseBindingText(t, false)
	return r
}

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

func pendingItem(status string, expires time.Time) PendingItem {
	n := caseNotice(caseShortLink)
	return PendingItem{
		Approval: action.Approval{ID: uuid.MustParse(caseApproval), Status: status, ExpiresAt: expires},
		Notice:   n,
	}
}

func resultCases() map[string]resultCase {
	revertArgs := map[string]any{"revertId": caseRevertID}
	run := action.Scope{Kind: revert.ScopeRun, ID: uuid.MustParse(caseRunID)}
	task := action.Scope{Kind: revert.ScopeTask, ID: uuid.MustParse(caseRunID)}
	state := func(status string) func(*testing.T, *Service) (string, []toolresult.Link, []toolresult.NextStep) {
		return func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
			out, err := s.revertState(context.Background(), caseRevertWith(t, status))
			require.NoError(t, err)
			return out.PersonMessage, out.Links, out.NextSteps
		}
	}
	batch := func(status string) func(*testing.T, *Service) (string, []toolresult.Link, []toolresult.NextStep) {
		return func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
			person, steps, err := s.batchGuidance(action.BatchResult{
				RevertID: uuid.MustParse(caseRevertID), Batch: 5, Status: status, Restored: 1000, Skipped: 9,
			})
			require.NoError(t, err)
			return person, nil, steps
		}
	}
	tooLargeRevert := func(t *testing.T, s *Service) action.Revert {
		s.deps.Core.PagesOrigin = ""
		r := caseRevertWith(t, ledger.RevertPending)
		r.Lines, r.LinesLeftOut, r.LinesCost = nil, true, 2<<20
		return r
	}
	cases := map[string]resultCase{
		resultKey("request_revert", "REQUEST_TOO_LARGE"): {
			tool: "request_revert", args: map[string]any{"revertId": caseRevertID, "reissueLink": true},
			build: func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
				out, err := s.revertWithLink(context.Background(), tooLargeRevert(t, s))
				require.NoError(t, err)
				require.Equal(t, "http://localhost:8787/reverts/"+caseRevertID, out.RevertURL, "the page's address, no fragment")
				return out.PersonMessage, out.Links, out.NextSteps
			},
		},
		resultKey("revert_plan", "REQUEST_TOO_LARGE"): {
			tool: "revert_plan", args: revertArgs,
			build: func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
				r := tooLargeRevert(t, s)
				n, err := s.revertNotice(context.Background(), r)
				require.NoError(t, err)
				require.True(t, n.tooLarge)
				person, steps, err := s.planGuidance(RevertPlan{Revert: r, RevertURL: n.URL, PersonMessage: n.Message, tooLarge: true})
				require.NoError(t, err)
				return person, nil, steps
			},
		},
		resultKey("list_pending", "REQUEST_TOO_LARGE"): {
			tool: "list_pending", args: map[string]any{},
			build: func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
				n := tooLargeNotice(t, s, keepLink)
				item := PendingItem{
					Approval: action.Approval{ID: uuid.MustParse(caseApproval), Status: ledger.ApprovalPending, ExpiresAt: s.deps.Core.Now().Add(time.Hour)},
					Notice:   n.ApprovalNotice, tooLargeSteps: n.steps,
				}
				person, links, steps, err := s.itemGuidance(item)
				require.NoError(t, err)
				return person, links, steps
			},
		},
		resultKey("preview_revert", "PREVIEW"): {
			tool: "preview_revert", args: map[string]any{"runId": caseRunID},
			build: func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
				person, steps, err := s.previewGuidance(RevertPreview{Scope: run, Rows: 3, Skipped: 1})
				require.NoError(t, err)
				return person, nil, steps
			},
		},
		resultKey("preview_revert", "PREVIEW_TASK"): {
			tool: "preview_revert", args: map[string]any{"taskId": caseRunID},
			build: func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
				person, steps, err := s.previewGuidance(RevertPreview{Scope: task, Rows: 3, Skipped: 1})
				require.NoError(t, err)
				return person, nil, steps
			},
		},

		resultKey("request_revert", "REQUESTED"): {
			tool: "request_revert", args: map[string]any{"runId": caseRunID, "intent": "Undo"},
			build: func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
				out, err := s.revertWithLink(context.Background(), caseRevertWith(t, ledger.RevertPending))
				require.NoError(t, err)
				return out.PersonMessage, out.Links, out.NextSteps
			},
		},
		resultKey("request_revert", "REQUESTED_NO_PAGES"): {
			tool: "request_revert", args: map[string]any{"runId": caseRunID, "intent": "Undo"},
			build: func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
				s.deps.Core.PagesOrigin = "" // no local pages and no Vault: a long link, review only
				out, err := s.revertWithLink(context.Background(), caseRevertWith(t, ledger.RevertPending))
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

		resultKey("list_pending", "PENDING"): {
			tool: "list_pending", args: map[string]any{},
			build: func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
				person, links, steps, err := s.itemGuidance(pendingItem(ledger.ApprovalPending, s.deps.Core.Now().Add(time.Hour)))
				require.NoError(t, err)
				return person, links, steps
			},
		},
		resultKey("list_pending", "EXPIRED"): {
			tool: "list_pending", args: map[string]any{},
			build: func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
				person, links, steps, err := s.itemGuidance(pendingItem(ledger.ApprovalPending, s.deps.Core.Now().Add(-time.Hour)))
				require.NoError(t, err)
				return person, links, steps
			},
		},
		resultKey("list_pending", "REVERT_PENDING"): {
			tool: "list_pending", args: map[string]any{}, openWithoutURL: true,
			build: func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
				p := &PendingRevert{Revert: caseRevertWith(t, ledger.RevertPending)}
				require.NoError(t, s.pendingRevert(context.Background(), p, false))
				return p.PersonMessage, p.Links, p.NextSteps
			},
		},
		resultKey("list_pending", "REVERT_APPLYING"): {
			tool: "list_pending", args: map[string]any{},
			build: func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
				p := &PendingRevert{Revert: caseBatchedRevert(t, ledger.RevertApplying)}
				require.NoError(t, s.pendingRevert(context.Background(), p, false))
				return p.PersonMessage, p.Links, p.NextSteps
			},
		},

		resultKey("revert_plan", "PENDING"): {
			tool: "revert_plan", args: revertArgs,
			build: func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
				return planGuidanceOf(t, s, caseBatchedRevert(t, ledger.RevertPending), nil)
			},
		},
		resultKey("revert_plan", "APPLYING"): {
			tool: "revert_plan", args: revertArgs,
			build: func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
				return planGuidanceOf(t, s, caseBatchedRevert(t, ledger.RevertApplying), planItems(guardmodel.OutcomePending, 202, 203, 204))
			},
		},
		resultKey("revert_plan", "APPLIED"): {
			tool: "revert_plan", args: revertArgs,
			build: func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
				return planGuidanceOf(t, s, caseBatchedRevert(t, ledger.RevertApplied), nil)
			},
		},
		resultKey("revert_plan", "EXPIRED"): {
			tool: "revert_plan", args: revertArgs,
			build: func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
				return planGuidanceOf(t, s, caseBatchedRevert(t, ledger.RevertExpired), nil)
			},
		},
		resultKey("revert_plan", "REJECTED"): {
			tool: "revert_plan", args: revertArgs,
			build: func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
				r := caseBatchedRevert(t, ledger.RevertRejected)
				r.RejectNote = "Not now."
				return planGuidanceOf(t, s, r, nil)
			},
		},

		resultKey("describe", "OVERVIEW_LARGE"): {
			tool: "describe", args: map[string]any{},
			build: func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
				b := guidance.NewSteps()
				overviewLargeSteps(b, []SchemaCount{{Schema: "app", Tables: 40}, {Schema: "billing", Tables: 12}})
				steps, err := b.Build()
				require.NoError(t, err)
				return "", nil, steps
			},
		},
		resultKey("describe", "NOT_GRANTED"): {
			tool: "describe", args: map[string]any{},
			build: func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
				b := guidance.NewSteps()
				person := s.describe.notGrantedSteps(b, 3)
				steps, err := b.Build()
				require.NoError(t, err)
				return person, nil, steps
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
	maps.Copy(cases, confirmResultCases())
	maps.Copy(cases, pluginResultCases())
	return cases
}

func resultService(t *testing.T, goos, config string) *Service {
	t.Helper()
	s := serviceFor(t, goos, config)
	s.deps.Core.PagesOrigin = "http://localhost:7878"
	s.deps.Core.Now = func() time.Time { return time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC) }
	return s
}

func TestEveryCatalogResultHasACase(t *testing.T) {
	t.Parallel()
	cases := resultCases()
	seen := map[string]bool{}
	var missing []string
	for _, e := range catalogOf(t).Results {
		key := resultKey(e.Tool, e.Case)
		seen[key] = true
		if _, ok := cases[key]; !ok {
			missing = append(missing, key)
		}
	}
	require.Empty(t, missing, "catalog results without a case in resultCases")
	var stale []string
	for k := range cases {
		if !seen[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)
	require.Empty(t, stale, "result cases without a catalog entry")
}

func TestEveryCatalogResultGivesTheCatalogsSteps(t *testing.T) {
	t.Parallel()
	for _, variant := range []struct {
		name, goos, config string
		initArgs           []string
	}{
		{"default config", "linux", "", []string{"--agent=bot", "--write=public.leads"}},
		{"custom config", "darwin", "/srv/basalt/engine.json", []string{"--agent=bot", "--read=public.leads"}},
	} {
		for _, entry := range catalogOf(t).Results {
			kase := resultCases()[resultKey(entry.Tool, entry.Case)]
			t.Run(variant.name+"/"+resultKey(entry.Tool, entry.Case), func(t *testing.T) {
				t.Parallel()
				s := resultService(t, variant.goos, variant.config)
				person, links, steps := kase.build(t, s)
				requireObeysCatalogSteps(t, mcpcontract.ErrorSteps{PersonMessage: entry.PersonMessage, Steps: entry.Steps},
					catalogCase{tool: kase.tool, args: kase.args}, person, links, steps, kase.openWithoutURL)
			})
		}
	}
}

// requireObeysCatalogSteps checks a result's or warning's person message and
// steps against its catalog entry and the rules every step follows.
func requireObeysCatalogSteps(t *testing.T, entry mcpcontract.ErrorSteps, kase catalogCase, person string, links []toolresult.Link, steps []toolresult.NextStep, openWithoutURL bool) {
	t.Helper()
	got := catalogKinds(steps)
	require.Equal(t, mcpcontract.Resolve(entry.Steps, mcpcontract.OperatedByPerson), got, "(actor, action) sequence")
	require.Equal(t, entry.PersonMessage, person != "", "personMessage set exactly when the catalog says: %q", person)
	mcptest.Require(t, person, links)
	for i, st := range steps {
		if st.Action == toolresult.ActionOpenLink && st.URL == "" && openWithoutURL {
			st.URL = "http://localhost/the-link-given-earlier"
		}
		requireStepObeysRules(t, st, kase, "step "+string(rune('1'+i)))
	}
}

func TestWaitEndedNamesTheLongLinkOnlyWithoutPages(t *testing.T) {
	t.Parallel()
	s := resultService(t, "linux", "")
	short, err := s.revertState(context.Background(), caseRevertWith(t, ledger.RevertPending))
	require.NoError(t, err)
	require.Empty(t, short.NextSteps[0].URL, "the short link was given earlier: no url")
	require.NotContains(t, short.PersonMessage, "http")

	s.deps.Core.PagesOrigin = ""
	long, err := s.revertState(context.Background(), caseRevertWith(t, ledger.RevertPending))
	require.NoError(t, err)
	require.NotEmpty(t, long.NextSteps[0].URL, "no pages: the long link is the only link")
}

func TestRequestedPersonMessageKeepsItsLimitWithALongIntent(t *testing.T) {
	t.Parallel()
	for _, pages := range []bool{true, false} {
		s := resultService(t, "linux", "")
		if !pages {
			s.deps.Core.PagesOrigin = ""
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
	_, _, steps := planGuidanceOf(t, s, caseBatchedRevert(t, ledger.RevertApplying), planItems(guardmodel.OutcomeRestored, 1, 2))
	require.Equal(t, guidance.ToolRevertPlan, steps[0].Tool)
	require.Equal(t, true, steps[0].Arguments["pending"])

	_, _, steps = planGuidanceOf(t, s, caseBatchedRevert(t, ledger.RevertApplying), planItems(guardmodel.OutcomePending, 5, 6))
	require.Equal(t, guidance.ToolApplyRevertBatch, steps[0].Tool)
	require.Equal(t, []int{5, 6}, steps[0].Arguments["lines"])
}

func TestAnApprovedPendingItemNeedsNothingFromThePerson(t *testing.T) {
	t.Parallel()
	s := resultService(t, "linux", "")
	_, _, steps, err := s.itemGuidance(pendingItem(ledger.ApprovalApproved, s.deps.Core.Now().Add(time.Hour)))
	require.NoError(t, err)
	require.Empty(t, steps)
}

// --- warnings ---

type warningCase struct {
	tool  string
	build func(t *testing.T, s *Service) []toolresult.Warning
}

func warningCases() map[string]warningCase {
	return map[string]warningCase{
		toolresult.WarningRLSHidesRows: {tool: "query", build: func(t *testing.T, s *Service) []toolresult.Warning {
			s.deps.Write.RLS = &fakeRLS{hidden: map[string]bool{"public.leads": true}}
			return s.rlsWarnings(context.Background(), []string{"public.leads"}, 0)
		}},
		toolresult.WarningGuardUpgradeAvailable: {tool: "run_start", build: func(t *testing.T, s *Service) []toolresult.Warning {
			s.deps.Status.Upgrade = fakeUpgrade{available: true}
			return s.upgradeWarnings(context.Background())
		}},
	}
}

func TestEveryCatalogWarningHasACase(t *testing.T) {
	t.Parallel()
	cases := warningCases()
	seen := map[string]bool{}
	for _, e := range catalogOf(t).Warnings {
		seen[e.Code] = true
		require.Contains(t, cases, e.Code, "catalog warning without a case in warningCases")
	}
	for code := range cases {
		require.True(t, seen[code], "warning case %s without a catalog entry", code)
	}
}

func TestEveryCatalogWarningGivesTheCatalogsSteps(t *testing.T) {
	t.Parallel()
	for _, variant := range []struct {
		name, goos, config string
		initArgs           []string
	}{
		{"default config", "linux", "", []string{"--agent=bot", "--write=public.leads"}},
		{"custom config", "darwin", "/srv/basalt/engine.json", []string{"--agent=bot", "--read=public.leads"}},
	} {
		for _, entry := range catalogOf(t).Warnings {
			kase := warningCases()[entry.Code]
			t.Run(variant.name+"/"+entry.Code, func(t *testing.T) {
				t.Parallel()
				s := resultService(t, variant.goos, variant.config)
				warnings := kase.build(t, s)
				require.Len(t, warnings, 1)
				w := warnings[0]
				require.Equal(t, entry.Code, w.Code)
				require.NotEmpty(t, w.Message)
				requireObeysCatalogSteps(t, mcpcontract.ErrorSteps{PersonMessage: entry.PersonMessage, Steps: entry.Steps},
					catalogCase{tool: kase.tool}, w.PersonMessage, nil, w.NextSteps, false)
			})
		}
	}
}

// On an agent-operated engine each warning takes its agentOperated variant:
// the agent makes a setup code instead of the person running an admin
// command on the agent's machine.
func TestEveryCatalogWarningGivesTheVariantOnAnAgentOperatedEngine(t *testing.T) {
	t.Parallel()
	for _, entry := range catalogOf(t).Warnings {
		kase := warningCases()[entry.Code]
		t.Run(entry.Code, func(t *testing.T) {
			t.Parallel()
			s := operatedService(t, "linux", "", mcpcontract.OperatedByAgent)
			s.deps.Core.PagesOrigin = "http://localhost:7878"
			warnings := kase.build(t, s)
			require.Len(t, warnings, 1)
			w := warnings[0]
			want, pm, variant := expectedSteps(t, mcpcontract.VariantWarning, entry.Code, "", "", entry.Steps, entry.PersonMessage, mcpcontract.OperatedByAgent)
			got := make([]mcpcontract.StepKind, 0, len(w.NextSteps))
			for _, st := range w.NextSteps {
				got = append(got, mcpcontract.StepKind{Actor: st.Actor, Action: st.Action})
			}
			require.Equal(t, want, got)
			require.Equal(t, pm, w.PersonMessage != "")
			mcptest.Require(t, w.PersonMessage, nil)
			requireOperatorRules(t, w.NextSteps, w.PersonMessage, variant, mcpcontract.OperatedByAgent, entry.Code)
			for i, st := range w.NextSteps {
				requireStepObeysRules(t, st, catalogCase{tool: kase.tool}, "step "+strconv.Itoa(i+1))
			}
		})
	}
}

func TestRLSWarningNamesTheTableAndOnlyAppearsOnZeroRows(t *testing.T) {
	t.Parallel()
	s := resultService(t, "linux", "")
	rls := &fakeRLS{hidden: map[string]bool{"public.secrets": true}}
	s.deps.Write.RLS = rls

	require.Empty(t, s.rlsWarnings(context.Background(), []string{"public.secrets"}, 3), "rows came back: no warning, no check")
	require.Zero(t, rls.asked)
	require.Empty(t, s.rlsWarnings(context.Background(), []string{"public.leads"}, 0), "a table RLS does not hide")

	warnings := s.rlsWarnings(context.Background(), []string{"public.leads", "public.secrets"}, 0)
	require.Len(t, warnings, 1)
	require.Equal(t, `"public"."secrets"`, warnings[0].Table)
	require.Contains(t, warnings[0].PersonMessage, `"public"."secrets"`, "the database's name, not the agent's spelling")
}

func TestRLSCheckFailureGivesNoWarning(t *testing.T) {
	t.Parallel()
	s := resultService(t, "linux", "")
	s.deps.Write.RLS = &fakeRLS{err: errors.New("down")}
	require.Empty(t, s.rlsWarnings(context.Background(), []string{"public.leads"}, 0))
	s.deps.Status.Upgrade = fakeUpgrade{err: errors.New("down")}
	require.Empty(t, s.upgradeWarnings(context.Background()))
	s.deps.Status.Upgrade = fakeUpgrade{}
	require.Empty(t, s.upgradeWarnings(context.Background()), "no migration missing: no warning")
}

func TestBlindCacheAsksOncePerTableUntilRefreshed(t *testing.T) {
	t.Parallel()
	asked := 0
	hidden := true
	cache := NewBlindCache(func(_ context.Context, tables []string) ([]string, error) {
		asked++
		if hidden {
			return []string{"public.leads"}, nil
		}
		return nil, nil
	})
	for range 3 {
		got, err := cache.Hides(context.Background(), "leads")
		require.NoError(t, err)
		require.Equal(t, "public.leads", got)
	}
	require.Equal(t, 1, asked)

	hidden = false
	got, err := cache.Hides(context.Background(), "leads")
	require.NoError(t, err)
	require.Equal(t, "public.leads", got, "still the cached answer")
	cache.Refresh()
	got, err = cache.Hides(context.Background(), "leads")
	require.NoError(t, err)
	require.Empty(t, got, "refreshed with the upkeep cycle")
	require.Equal(t, 2, asked)
}

// A refresh between the question and the store must not leave the old answer.
func TestBlindCacheDropsAnAnswerAskedBeforeARefresh(t *testing.T) {
	t.Parallel()
	var cache *BlindCache
	cache = NewBlindCache(func(context.Context, []string) ([]string, error) {
		cache.Refresh() // the upkeep cycle runs while the question is out
		return []string{"public.leads"}, nil
	})
	got, err := cache.Hides(context.Background(), "leads")
	require.NoError(t, err)
	require.Equal(t, "public.leads", got)
	require.Empty(t, cache.known, "the stale answer was not stored")
}

// Text the agent or the database supplies cannot fake a link line in a
// message the person reads: an intent with a blank line and a URL, a table
// whose name holds one.
func TestSuppliedTextCannotFakeALinkInAPersonMessage(t *testing.T) {
	t.Parallel()
	const evil = "Fix it.\n\nhttps://evil.example/pay\n\nthen sign"
	s := resultService(t, "linux", "")

	r := caseRevertWith(t, ledger.RevertPending)
	raw, err := json.Marshal(revert.Binding{
		Kind: revert.KindRevert, RevertID: r.ID, Database: "app",
		Select: revert.Select{Scope: revert.ScopeRun, ScopeID: r.ScopeID, Agents: []string{"bot"}},
		Intent: evil, Rows: 3, Skipped: 1, RowsHash: strings.Repeat("a", 64), ExpiresAt: r.ExpiresAt, RequestedBy: "bot",
	})
	require.NoError(t, err)
	r.BindingText = string(raw)
	n, err := s.revertNotice(context.Background(), r)
	require.NoError(t, err)
	mcptest.Require(t, n.Message, n.Links)
	require.Len(t, n.Links, 1, "only the link the engine hands over")
	require.NotContains(t, n.Message, "https://evil", "the supplied URL is text, not a link")
	require.Len(t, urlLinesOf(n.Message), 1)

	table := "public.x\n\nhttps://evil.example/pay\n\ny"
	s.deps.Write.RLS = &fakeRLS{hidden: map[string]bool{table: true}}
	warnings := s.rlsWarnings(context.Background(), []string{table}, 0)
	require.Len(t, warnings, 1)
	mcptest.Require(t, warnings[0].PersonMessage, nil)
	require.NotContains(t, warnings[0].PersonMessage, "://")
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

// catalogKinds is the (actor, action) sequence of steps as the catalog lists
// it: without the SEND_REQUEST step the engine puts first when a result
// carries requestFile (CONTRACT.md, Next steps).
func catalogKinds(steps []toolresult.NextStep) []mcpcontract.StepKind {
	got := make([]mcpcontract.StepKind, 0, len(steps))
	for i, st := range steps {
		if i == 0 && st.Action == toolresult.ActionSendRequest {
			continue
		}
		got = append(got, mcpcontract.StepKind{Actor: st.Actor, Action: st.Action})
	}
	return got
}
