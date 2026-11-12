package agent

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/mcp/mcptest"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// resultCase builds one result of the catalog: the person's message and the
// next steps it carries, for the tool and the call that returned it.
type resultCase struct {
	tool string
	args map[string]any
	// build returns the result's personMessage and nextSteps.
	build func(t *testing.T, s *Service) (string, []mcp.Link, []mcp.NextStep)
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

func caseRevertWith(t *testing.T, status string) ledger.Revert {
	t.Helper()
	r := caseRevert(false)
	r.Status, r.Rows, r.Skipped, r.BindingText = status, 3, 1, caseBindingText(t, false)
	return r
}

func caseBatchedRevert(t *testing.T, status string) ledger.Revert {
	t.Helper()
	r := caseRevert(true)
	r.Status, r.Batched, r.Rows, r.Skipped = status, true, 1209, 1
	r.BindingText = caseBindingText(t, true)
	apply := r.ExpiresAt.Add(24 * time.Hour)
	r.ApplyBy = &apply
	r.Progress = ledger.RevertProgress{Restored: 200, Skipped: 1, Pending: 1009}
	return r
}

func planItems(outcome string, nos ...int) []RevertPlanLine {
	out := make([]RevertPlanLine, 0, len(nos))
	for _, n := range nos {
		out = append(out, RevertPlanLine{RevertLine: ledger.RevertLine{No: n, Outcome: outcome}})
	}
	return out
}

func planGuidanceOf(t *testing.T, s *Service, r ledger.Revert, items []RevertPlanLine) (string, []mcp.Link, []mcp.NextStep) {
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

func pendingItem(s *Service, status string, expires time.Time) PendingItem {
	n := caseNotice(s, caseShortLink)
	return PendingItem{
		Approval: ledger.Approval{ID: uuid.MustParse(caseApproval), Status: status, ExpiresAt: expires},
		Notice:   n,
	}
}

func resultCases() map[string]resultCase {
	revertArgs := map[string]any{"revertId": caseRevertID}
	run := guard.RevertScope{Kind: revert.ScopeRun, ID: uuid.MustParse(caseRunID)}
	task := guard.RevertScope{Kind: revert.ScopeTask, ID: uuid.MustParse(caseRunID)}
	state := func(status string) func(*testing.T, *Service) (string, []mcp.Link, []mcp.NextStep) {
		return func(t *testing.T, s *Service) (string, []mcp.Link, []mcp.NextStep) {
			out, err := s.revertState(context.Background(), caseRevertWith(t, status))
			require.NoError(t, err)
			return out.PersonMessage, out.Links, out.NextSteps
		}
	}
	batch := func(status string) func(*testing.T, *Service) (string, []mcp.Link, []mcp.NextStep) {
		return func(t *testing.T, s *Service) (string, []mcp.Link, []mcp.NextStep) {
			person, steps, err := s.batchGuidance(guard.BatchResult{
				RevertID: uuid.MustParse(caseRevertID), Batch: 5, Status: status, Restored: 1000, Skipped: 9,
			})
			require.NoError(t, err)
			return person, nil, steps
		}
	}
	return map[string]resultCase{
		resultKey("preview_revert", "PREVIEW"): {tool: "preview_revert", args: map[string]any{"runId": caseRunID},
			build: func(t *testing.T, s *Service) (string, []mcp.Link, []mcp.NextStep) {
				person, steps, err := s.previewGuidance(RevertPreview{Scope: run, Rows: 3, Skipped: 1})
				require.NoError(t, err)
				return person, nil, steps
			}},
		resultKey("preview_revert", "PREVIEW_TASK"): {tool: "preview_revert", args: map[string]any{"taskId": caseRunID},
			build: func(t *testing.T, s *Service) (string, []mcp.Link, []mcp.NextStep) {
				person, steps, err := s.previewGuidance(RevertPreview{Scope: task, Rows: 3, Skipped: 1})
				require.NoError(t, err)
				return person, nil, steps
			}},

		resultKey("request_revert", "REQUESTED"): {tool: "request_revert", args: map[string]any{"runId": caseRunID, "intent": "Undo"},
			build: func(t *testing.T, s *Service) (string, []mcp.Link, []mcp.NextStep) {
				out, err := s.revertWithLink(context.Background(), caseRevertWith(t, ledger.RevertPending))
				require.NoError(t, err)
				return out.PersonMessage, out.Links, out.NextSteps
			}},
		resultKey("request_revert", "WAIT_ENDED"): {tool: "request_revert", args: revertArgs, openWithoutURL: true,
			build: state(ledger.RevertPending)},
		resultKey("request_revert", "APPLYING"): {tool: "request_revert", args: revertArgs, build: state(ledger.RevertApplying)},
		resultKey("request_revert", "APPLIED"):  {tool: "request_revert", args: revertArgs, build: state(ledger.RevertApplied)},
		resultKey("request_revert", "EXPIRED"):  {tool: "request_revert", args: revertArgs, build: state(ledger.RevertExpired)},

		resultKey("list_pending", "PENDING"): {tool: "list_pending", args: map[string]any{},
			build: func(t *testing.T, s *Service) (string, []mcp.Link, []mcp.NextStep) {
				person, links, steps, err := s.itemGuidance(pendingItem(s, ledger.ApprovalPending, s.Now().Add(time.Hour)))
				require.NoError(t, err)
				return person, links, steps
			}},
		resultKey("list_pending", "EXPIRED"): {tool: "list_pending", args: map[string]any{},
			build: func(t *testing.T, s *Service) (string, []mcp.Link, []mcp.NextStep) {
				person, links, steps, err := s.itemGuidance(pendingItem(s, ledger.ApprovalPending, s.Now().Add(-time.Hour)))
				require.NoError(t, err)
				return person, links, steps
			}},

		resultKey("revert_plan", "PENDING"): {tool: "revert_plan", args: revertArgs,
			build: func(t *testing.T, s *Service) (string, []mcp.Link, []mcp.NextStep) {
				return planGuidanceOf(t, s, caseBatchedRevert(t, ledger.RevertPending), nil)
			}},
		resultKey("revert_plan", "APPLYING"): {tool: "revert_plan", args: revertArgs,
			build: func(t *testing.T, s *Service) (string, []mcp.Link, []mcp.NextStep) {
				return planGuidanceOf(t, s, caseBatchedRevert(t, ledger.RevertApplying), planItems(ledger.OutcomePending, 202, 203, 204))
			}},
		resultKey("revert_plan", "APPLIED"): {tool: "revert_plan", args: revertArgs,
			build: func(t *testing.T, s *Service) (string, []mcp.Link, []mcp.NextStep) {
				return planGuidanceOf(t, s, caseBatchedRevert(t, ledger.RevertApplied), nil)
			}},
		resultKey("revert_plan", "EXPIRED"): {tool: "revert_plan", args: revertArgs,
			build: func(t *testing.T, s *Service) (string, []mcp.Link, []mcp.NextStep) {
				return planGuidanceOf(t, s, caseBatchedRevert(t, ledger.RevertExpired), nil)
			}},

		resultKey("apply_revert_batch", "APPLYING"): {tool: "apply_revert_batch", args: map[string]any{"revertId": caseRevertID, "lines": []any{1}},
			build: batch(ledger.RevertApplying)},
		resultKey("apply_revert_batch", "APPLIED"): {tool: "apply_revert_batch", args: map[string]any{"revertId": caseRevertID, "lines": []any{1}},
			build: batch(ledger.RevertApplied)},
	}
}

func resultService(t *testing.T, goos, config string, initArgs []string) *Service {
	t.Helper()
	s := serviceFor(t, goos, config, initArgs)
	s.PagesOrigin = "http://localhost:7878"
	s.Now = func() time.Time { return time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC) }
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
				s := resultService(t, variant.goos, variant.config, variant.initArgs)
				person, links, steps := kase.build(t, s)
				requireObeysCatalogSteps(t, mcpcontract.ErrorSteps{PersonMessage: entry.PersonMessage, Steps: entry.Steps},
					catalogCase{tool: kase.tool, args: kase.args}, person, links, steps, variant.config, kase.openWithoutURL)
			})
		}
	}
}

// requireObeysCatalogSteps checks a result's or warning's person message and
// steps against its catalog entry and the rules every step follows.
func requireObeysCatalogSteps(t *testing.T, entry mcpcontract.ErrorSteps, kase catalogCase, person string, links []mcp.Link, steps []mcp.NextStep, config string, openWithoutURL bool) {
	t.Helper()
	got := make([]mcpcontract.StepKind, 0, len(steps))
	for _, st := range steps {
		got = append(got, mcpcontract.StepKind{Actor: st.Actor, Action: st.Action})
	}
	require.Equal(t, mcpcontract.Resolve(entry.Steps, mcpcontract.OperatedByPerson), got, "(actor, action) sequence")
	require.Equal(t, entry.PersonMessage, person != "", "personMessage set exactly when the catalog says: %q", person)
	mcptest.Require(t, person, links)
	for i, st := range steps {
		if st.Action == mcp.ActionOpenLink && st.URL == "" && openWithoutURL {
			st.URL = "http://localhost/the-link-given-earlier"
		}
		requireStepObeysRules(t, st, kase, config, "step "+string(rune('1'+i)))
	}
}

func TestWaitEndedNamesTheLongLinkOnlyWithoutPages(t *testing.T) {
	t.Parallel()
	s := resultService(t, "linux", "", []string{"--agent=bot"})
	short, err := s.revertState(context.Background(), caseRevertWith(t, ledger.RevertPending))
	require.NoError(t, err)
	require.Empty(t, short.NextSteps[0].URL, "the short link was given earlier: no url")
	require.NotContains(t, short.PersonMessage, "http")

	s.PagesOrigin = ""
	long, err := s.revertState(context.Background(), caseRevertWith(t, ledger.RevertPending))
	require.NoError(t, err)
	require.NotEmpty(t, long.NextSteps[0].URL, "no pages: the long link is the only link")
}

func TestRequestedPersonMessageKeepsItsLimitWithALongIntent(t *testing.T) {
	t.Parallel()
	for _, pages := range []bool{true, false} {
		s := resultService(t, "linux", "", []string{"--agent=bot"})
		if !pages {
			s.PagesOrigin = ""
		}
		n, err := s.revertNotice(context.Background(), caseRevertWith(t, ledger.RevertPending))
		require.NoError(t, err)
		mcptest.Require(t, n.Message, n.Links)
		require.Contains(t, n.Message, "http", "the link is in the message")
	}
}

func TestApplyingStepsListPendingLinesWhenThePageHasNone(t *testing.T) {
	t.Parallel()
	s := resultService(t, "linux", "", []string{"--agent=bot"})
	_, _, steps := planGuidanceOf(t, s, caseBatchedRevert(t, ledger.RevertApplying), planItems(ledger.OutcomeRestored, 1, 2))
	require.Equal(t, toolRevertPlan, steps[0].Tool)
	require.Equal(t, true, steps[0].Arguments["pending"])

	_, _, steps = planGuidanceOf(t, s, caseBatchedRevert(t, ledger.RevertApplying), planItems(ledger.OutcomePending, 5, 6))
	require.Equal(t, toolApplyRevertBatch, steps[0].Tool)
	require.Equal(t, []int{5, 6}, steps[0].Arguments["lines"])
}

func TestAnApprovedPendingItemNeedsNothingFromThePerson(t *testing.T) {
	t.Parallel()
	s := resultService(t, "linux", "", []string{"--agent=bot"})
	_, _, steps, err := s.itemGuidance(pendingItem(s, ledger.ApprovalApproved, s.Now().Add(time.Hour)))
	require.NoError(t, err)
	require.Empty(t, steps)
}

// --- warnings ---

type warningCase struct {
	tool  string
	build func(t *testing.T, s *Service) []mcp.Warning
}

func warningCases() map[string]warningCase {
	return map[string]warningCase{
		mcp.WarningRLSHidesRows: {tool: "query", build: func(t *testing.T, s *Service) []mcp.Warning {
			s.RLS = &fakeRLS{hidden: map[string]bool{"public.leads": true}}
			return s.rlsWarnings(context.Background(), []string{"public.leads"}, 0)
		}},
		mcp.WarningGuardUpgradeAvailable: {tool: "run_start", build: func(t *testing.T, s *Service) []mcp.Warning {
			s.Upgrade = fakeUpgrade{available: true}
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
				s := resultService(t, variant.goos, variant.config, variant.initArgs)
				warnings := kase.build(t, s)
				require.Len(t, warnings, 1)
				w := warnings[0]
				require.Equal(t, entry.Code, w.Code)
				require.NotEmpty(t, w.Message)
				requireObeysCatalogSteps(t, mcpcontract.ErrorSteps{PersonMessage: entry.PersonMessage, Steps: entry.Steps},
					catalogCase{tool: kase.tool}, w.PersonMessage, nil, w.NextSteps, variant.config, false)
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
			s := operatedService(t, "linux", "", []string{"--agent=bot", "--write=public.leads", "--os-user=bot"}, mcpcontract.OperatedByAgent)
			s.PagesOrigin = "http://localhost:7878"
			warnings := kase.build(t, s)
			require.Len(t, warnings, 1)
			w := warnings[0]
			want, pm, variant := expectedSteps(t, mcpcontract.VariantWarning, entry.Code, "", "", entry.Steps, entry.PersonMessage, mcpcontract.OperatedByAgent)
			require.True(t, variant, "every warning has a variant")
			got := make([]mcpcontract.StepKind, 0, len(w.NextSteps))
			for _, st := range w.NextSteps {
				got = append(got, mcpcontract.StepKind{Actor: st.Actor, Action: st.Action})
			}
			require.Equal(t, want, got)
			require.Equal(t, pm, w.PersonMessage != "")
			mcptest.Require(t, w.PersonMessage, nil)
			requireOperatorRules(t, w.NextSteps, w.PersonMessage, variant, entry.Code)
			for i, st := range w.NextSteps {
				requireStepObeysRules(t, st, catalogCase{tool: kase.tool}, "", "step "+strconv.Itoa(i+1))
			}
		})
	}
}

func TestRLSWarningNamesTheTableAndOnlyAppearsOnZeroRows(t *testing.T) {
	t.Parallel()
	s := resultService(t, "linux", "", []string{"--agent=bot"})
	rls := &fakeRLS{hidden: map[string]bool{"public.secrets": true}}
	s.RLS = rls

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
	s := resultService(t, "linux", "", []string{"--agent=bot"})
	s.RLS = &fakeRLS{err: errors.New("down")}
	require.Empty(t, s.rlsWarnings(context.Background(), []string{"public.leads"}, 0))
	s.Upgrade = fakeUpgrade{err: errors.New("down")}
	require.Empty(t, s.upgradeWarnings(context.Background()))
	s.Upgrade = fakeUpgrade{}
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
	s := resultService(t, "linux", "", []string{"--agent=bot"})

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
	s.RLS = &fakeRLS{hidden: map[string]bool{table: true}}
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
